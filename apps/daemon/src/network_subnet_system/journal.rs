use super::*;
use nestlink_platform_security::{MetadataCommit,check_private_directory,create_private,read_private,replace_private_metadata};
use std::fs::{File,OpenOptions};

const JOURNAL:&str="network-subnet-owner.json";
#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Namespace {
    pub device:u64,
    pub inode:u64,
    pub worker:crate::space_dns_system::ProcessIdentity,
}
#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Journal {pub schema_version:u16,pub plan:Plan,pub parent:serde_json::Value,pub namespace:Option<Namespace>,pub receipt:Option<Receipt>}
pub(super) struct Store {pub directory:PathBuf,_lock:File}
impl Store {
    pub fn open(directory:&Path)->Result<Self> {
        if !directory.is_absolute() {return Err(io::Error::other("absolute root-private subnet journal directory required").into());}
        check_private_directory(directory)?;
        let directory=directory.canonicalize()?;
        let path=directory.join("network-subnet-owner.lock");
        match create_private(&path,&[]) {Ok(())=>{},Err(error) if error.kind()==io::ErrorKind::AlreadyExists=>{read_private(&path,1)?;},Err(error)=>return Err(error.into())}
        let lock=OpenOptions::new().read(true).write(true).open(path)?;
        if !lock.metadata()?.is_file()||lock.metadata()?.len()!=0 {return Err(io::Error::other("invalid subnet journal lock").into());}
        lock.try_lock().map_err(|_|io::Error::other("another root helper owns this subnet recovery journal"))?;
        Ok(Self{directory,_lock:lock})
    }
    pub fn path(&self)->PathBuf {self.directory.join(JOURNAL)}
    pub fn socket_path(&self)->PathBuf {self.directory.join("network-subnet-packet.sock")}
    pub fn read_path(path:&Path)->Result<Journal> {
        let journal:Journal=serde_json::from_slice(&read_private(path,MAX_JOURNAL)?)?;
        if journal.schema_version!=1 {return Err(io::Error::other("unsupported subnet journal schema").into());}
        journal.plan.checked(false)?;
        if let Some(namespace)=&journal.namespace {
            if namespace.device==0||namespace.inode==0||!namespace.worker.valid() {return Err(io::Error::other("invalid original namespace identity").into());}
            if let Some(receipt)=&journal.receipt {if receipt.namespace_device!=namespace.device||receipt.namespace_inode!=namespace.inode||receipt.worker!=namespace.worker||receipt.plan_digest!=journal.plan.digest()?||receipt.socket_device==0||receipt.socket_inode==0||receipt.socket_parent_device==0||receipt.socket_parent_inode==0 {return Err(io::Error::other("subnet receipt differs from original namespace/plan").into());}}
        } else if journal.receipt.is_some() {return Err(io::Error::other("subnet receipt lacks a durable namespace identity").into());}
        Ok(journal)
    }
    pub fn read(&self)->Result<Option<Journal>> {
        match Self::read_path(&self.path()) {Ok(journal)=>Ok(Some(journal)),Err(error) if error.downcast_ref::<io::Error>().is_some_and(|error|error.kind()==io::ErrorKind::NotFound)=>Ok(None),Err(error)=>Err(error)}
    }
    pub fn save(&self,journal:&Journal)->Result {
        let bytes=serde_json::to_vec(journal)?;
        if bytes.len() as u64>MAX_JOURNAL {return Err(io::Error::other("subnet journal exceeds its fixed byte budget").into());}
        if replace_private_metadata(&self.path(),&bytes)?!=MetadataCommit::Durable {return Err(io::Error::other("subnet journal durability is unknown; preserve original recovery state").into());}
        Ok(())
    }
    pub fn consume(&self,plan:&Plan)->Result {
        if std::fs::read_dir(&self.directory)?.take(65_540).count()>=65_538 {return Err(io::Error::other("subnet owner history is full; no original business may be reset").into());}
        use base64::{Engine,engine::general_purpose::URL_SAFE_NO_PAD};
        let path=self.directory.join(format!("consumed-{}.json",URL_SAFE_NO_PAD.encode(plan.approved_access)));
        create_private(&path,&serde_json::to_vec(&(plan.owner_id.clone(),plan.digest()?))?)?;
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
    pub fn clear(&self)->Result {std::fs::remove_file(self.path())?;File::open(&self.directory)?.sync_all()?;Ok(())}
}
const MAX_JOURNAL:u64=131_072;
