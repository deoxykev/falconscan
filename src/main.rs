use std::{
    sync::{Arc},
    time::Duration, path::Path,
    sync::mpsc::channel,
};
use futures::FutureExt;
use tokio::{
    self, join, task, time,
    // sync::mpsc::channel,
};
use anyhow::Result;
mod crowdstrike;
mod sql;
mod scanner;
mod worker;
use scanner::{scan};
use crowdstrike::Crowdstrike;
use r2d2;
use r2d2_sqlite;

use notify::{RecommendedWatcher, Watcher, RecursiveMode, DebouncedEvent};
use clap::Parser;


#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Directory to scan 
    #[clap(short, long)]
    dir: String,

    /// Savefile to use 
    #[clap(short, long, default_value = "./cs_scan.sqlite")]
    save: String,

    /// Number of concurrent jobs 
    #[clap(short, long, default_value_t = 20)]
    n: i64,
}

#[tokio::main]
async fn main() -> Result<()> {

    // parse args
    let args  = Args::parse();
    let scan_paths = args.dir;
    let max_jobs = args.n;
    let save_file = args.save;

    // setup db pool
    let manager = r2d2_sqlite::SqliteConnectionManager::file(save_file.clone());
    let pool = r2d2::Pool::builder()
        .max_size(20)
        .build(manager)?;
    let pool = Arc::new(pool);
    let db = sql::DB::new(save_file.as_str())?;

    // setup crowdstrike client
    // let cs = Crowdstrike::from_env().await?;
    let cs = Crowdstrike::new(
        String::from("api.crowdstrike.com"),
        String::from("xxxxx"),
        String::from("xxxxx"),
        reqwest::Client::new() 
    ).await.unwrap();
    let cs = Arc::new(cs);
    let cs1 = Arc::clone(&cs); // token refresher
    let cs2 = Arc::clone(&cs); // worker executer

    // setup new file scanner
    let scan_pool = pool.clone();
    let dispatch_pool = pool.clone();
    let worker_pool = pool.clone();

    // full filesystem scan only once, then use notify hooks to add in new files
    let scanner = task::spawn(async move {
        println!("rescanning entire directory: {}", &scan_paths);
        let res = scan(scan_paths.clone(), scan_pool.clone(), db).await;
        if res.is_err() {
            println!("error with scan:: {:?}", res.unwrap_err())
        }
        println!("rescanning complete: {}", &scan_paths);

        let (tx, rx) = channel();
        let mut watcher: RecommendedWatcher = Watcher::new(tx, Duration::from_secs(2)).unwrap();
        watcher.watch(scan_paths.clone(), RecursiveMode::Recursive).unwrap();
        println!("watching for new changes to directory: {}", &scan_paths);
        loop {
            let rxx = rx.recv();
            match &rxx {
                Ok(event) => {
                    println!("new file: {:?}", event);
                    match event {
                        DebouncedEvent::Create(path) => {
                            db.check_file(scan_pool.clone(), path.clone()).await.unwrap();
                        },
                        DebouncedEvent::Write(path) => {
                            db.check_file(scan_pool.clone(), path.clone()).await.unwrap();
                        },
                        DebouncedEvent::NoticeWrite(path) => {
                            db.check_file(scan_pool.clone(), path.clone()).await.unwrap();
                        },
                        _ => (),
                    }
                },
                Err(e) => println!("watch error: {:?}", e),
            }
        }
    });

    // setup cs auth token refresher
    let token_refresher = task::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(1700)); // auth token lasts 30m
        interval.tick().await; // first tick t=0
        loop {
            interval.tick().await; // second tick t=1700
            cs1.refresh_auth_token()
                .await
                .expect("failed to refresh CS auth token");
            println!("refreshed cs auth token");
        }
    });

    // setup quickscan dispatcher 
    let dispatcher = task::spawn(async move {
        let mut interval = time::interval(Duration::from_millis(100));
        let mut waiting = false;

        loop {
            // check active jobs
            let active_jobs = db.active_jobs(dispatch_pool.clone())
                .await
                .expect("could not poll for number of current active jobs, possible sql error");

            // println!("active jobs: {}", active_jobs);
            if active_jobs >= max_jobs { 
                interval.tick().await;
                continue 
            }
 
            // todo: check cs quota before continueing

            let job = db.take_job(dispatch_pool.clone()).await;
            let x = job.unwrap();
            if let Some(job) = x {

                println!("dispatcher: dispatching job: {}", &job.path);
                let cst = Arc::clone(&cs2);
                let j = job.clone();
                let wp = worker_pool.clone();

                let mut task = task::spawn( async move {
                    // println!("spawning async worker task");
                    let res = worker::execute(
                        j,
                        wp,
                        db,
                        cst,
                    ).await;
                    if res.is_err() {
                        println!("failed async worker task: {}", res.unwrap_err());
                    }
                    // println!("finished spawning async worker task");
                });

                (&mut task).now_or_never();
                waiting = false;
            } else {
                if !waiting {
                    println!("dispatcher idle: waiting for new files");
                    waiting = true;
                }
            }
        }

    });

    let (_,_,_) = join!(scanner, dispatcher, token_refresher);

    Ok(())
}
