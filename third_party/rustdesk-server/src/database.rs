// sqlite persistence for hbbs (peers). Replaced the original sqlx 0.6
// implementation with rusqlite so the whole ReMgr binary links a single
// libsqlite3-sys (easytier-web's sqlx 0.8 pins another copy, and cargo
// forbids two `links = "sqlite3"` packages in one graph).

use hbb_common::{log, ResultType};
use rusqlite::Connection;
use std::sync::Mutex;

#[derive(Clone)]
pub struct Database {
    conn: std::sync::Arc<Mutex<Connection>>,
}

#[derive(Default)]
pub struct Peer {
    pub guid: Vec<u8>,
    pub id: String,
    pub uuid: Vec<u8>,
    pub pk: Vec<u8>,
    pub user: Option<Vec<u8>>,
    pub info: String,
    pub status: Option<i64>,
}

impl Database {
    pub async fn new(url: &str) -> ResultType<Database> {
        if !std::path::Path::new(url).exists() {
            std::fs::File::create(url).ok();
        }
        let conn = Connection::open(url)?;
        let db = Database { conn: std::sync::Arc::new(Mutex::new(conn)) };
        db.create_tables().await?;
        Ok(db)
    }

    async fn create_tables(&self) -> ResultType<()> {
        let conn = self.conn.clone();
        let _guard = hbb_common::tokio::task::spawn_blocking(move || -> ResultType<()> {
            let conn = conn.lock().unwrap();
            conn.execute_batch(
                "
            create table if not exists peer (
                guid blob primary key not null,
                id varchar(100) not null,
                uuid blob not null,
                pk blob not null,
                created_at datetime not null default(current_timestamp),
                user blob,
                status tinyint,
                note varchar(300),
                info text not null
            ) without rowid;
            create unique index if not exists index_peer_id on peer (id);
            create index if not exists index_peer_user on peer (user);
            create index if not exists index_peer_created_at on peer (created_at);
            create index if not exists index_peer_status on peer (status);
        ",
            )?;
            Ok(())
        })
        .await??;
        Ok(())
    }

    pub async fn get_peer(&self, id: &str) -> ResultType<Option<Peer>> {
        let conn = self.conn.clone();
        let id = id.to_owned();
        let res = hbb_common::tokio::task::spawn_blocking(move || -> ResultType<Option<Peer>> {
            let conn = conn.lock().unwrap();
            let mut stmt =
                conn.prepare("select guid, id, uuid, pk, user, status, info from peer where id = ?")?;
            let mut rows = stmt.query([&id])?;
            Ok(if let Some(row) = rows.next()? {
                Some(Peer {
                    guid: row.get(0)?,
                    id: row.get(1)?,
                    uuid: row.get(2)?,
                    pk: row.get(3)?,
                    user: row.get(4)?,
                    status: row.get(5)?,
                    info: row.get(6)?,
                })
            } else {
                None
            })
        })
        .await??;
        Ok(res)
    }

    pub async fn insert_peer(
        &self,
        id: &str,
        uuid: &[u8],
        pk: &[u8],
        info: &str,
    ) -> ResultType<Vec<u8>> {
        let conn = self.conn.clone();
        let id = id.to_owned();
        let uuid = uuid.to_vec();
        let pk = pk.to_vec();
        let info = info.to_owned();
        let guid = uuid::Uuid::new_v4().as_bytes().to_vec();
        let guid2 = guid.clone();
        hbb_common::tokio::task::spawn_blocking(move || -> ResultType<()> {
            let conn = conn.lock().unwrap();
            conn.execute(
                "insert into peer(guid, id, uuid, pk, info) values(?, ?, ?, ?, ?)",
                rusqlite::params![guid2, id, uuid, pk, info],
            )?;
            Ok(())
        })
        .await??;
        Ok(guid)
    }

    pub async fn update_pk(
        &self,
        guid: &Vec<u8>,
        id: &str,
        pk: &[u8],
        info: &str,
    ) -> ResultType<()> {
        let conn = self.conn.clone();
        let guid = guid.clone();
        let id = id.to_owned();
        let pk = pk.to_vec();
        let info = info.to_owned();
        hbb_common::tokio::task::spawn_blocking(move || -> ResultType<()> {
            let conn = conn.lock().unwrap();
            conn.execute(
                "update peer set id=?, pk=?, info=? where guid=?",
                rusqlite::params![id, pk, info, guid],
            )?;
            Ok(())
        })
        .await??;
        Ok(())
    }
}
