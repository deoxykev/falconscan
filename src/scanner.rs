use crate::sql::{ArcPool, DB};
use anyhow::{Result};
use walkdir::{WalkDir};
use std::{
    path::PathBuf,
    sync::Arc,
};
use futures::future::join_all;

// use notify::{RecommendedWatcher, Watcher, RecursiveMode};
// use std::sync::mpsc::channel;
// use std::time::Duration;



pub async fn scan(path: String, pool: ArcPool, db: &'static DB) -> Result<()> {
    let paths = WalkDir::new(path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok());

    let mut handles = Vec::new(); 

    for entry in paths {
        if !entry.metadata()?.is_file() { continue }

        // let p = entry.path();

        let pc = pool.clone();
        let pb = Arc::new(PathBuf::from(entry.path()));
        let pbb = pb.clone().to_path_buf();

        let handle = tokio::spawn(async move {
            db.check_file(pc, pbb)
        });
        handles.push(handle);
    }

    for i in join_all(handles).await {
        i?.await?;
    }



    Ok(())
}

mod test {
    use super::scan;
    use crate::sql;
    use crate::scanner::DB;
    use rusqlite::{self, params};
    use r2d2;
    use r2d2_sqlite;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_scan() {
        let db: &DB = sql::DB::new("./foo.sqlite").unwrap();

        let manager = r2d2_sqlite::SqliteConnectionManager::file("./foo.sqlite");
        let pool = r2d2::Pool::builder()
            .max_size(20)
            .build(manager)
            .expect("could not build pool");

        let pool = Arc::new(pool);

        scan("./target".to_string(), pool.clone(), db)
            .await
            .expect("test scan fail");

        // scan("./target", &db, &mut cache)
        // .expect("test scan fail");
    }
}
