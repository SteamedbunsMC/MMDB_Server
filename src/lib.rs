#![feature(fs_try_exists)]
//!MMDB - Server Side Program
pub use servermain::{crypt, decrypt, index, size};

///Server main module,include crypt,decypt and so on.
pub mod servermain {
    use std::io::Read;
    use std::{fs, process::ExitCode};
    use threadpool::*;

    use core::*;
    use std::{
        collections::HashMap,
        env,
        error::Error,
        io::{BufRead, BufReader, BufWriter, Write},
        marker::Send,
        net::{TcpListener, TcpStream},
        process,
        sync::{Arc, Mutex},
        thread::{self, JoinHandle},
    };

    /// Get the size of a &str
    /// ### Examples
    /// ```
    /// use MMDB_Server::size;
    /// assert!(size("abc") == 3);
    /// ```
    pub fn size(str: &str) -> i64 {
        let striter = str.chars().into_iter();
        let mut res = 0;
        for _i in striter {
            res = res + 1;
        }
        return res;
    }

    /// Index charactor in &str
    /// ### Examples
    /// ```
    /// use MMDB_Server::index;
    /// println!("{}",index("9w874ro8ysegfoyudgrifyugeudygddd",8) == 'y'); // output: true
    /// assert!(index("9w874ro8ysegfoyudgrifyugeudygddd",8) == 'y');
    /// ```
    /// ### Panics
    /// * Index out of range (index start from 0)
    /// * Unlegit &str (Use auto convert to convert utf-8 String to ASCII &str)
    pub fn index(str: &str, index: u64) -> char {
        let mut striter = str.chars().clone().into_iter();
        for _ in 0..index {
            let _ = striter.next();
        }
        return striter.next().unwrap();
    }

    /// Run server
    pub fn run() -> Result<(), Box<dyn Error>> {
        println!(" ***************   88888888888888        d  b");
        println!(" *     *       *   8     8      8        d  b");
        println!(" *     *       *   8     8      8        d  b");
        println!(" *     *       *   8     8      8        d  b");
        println!(" *     *       *   8     8      8  ddddddd  bbbbbbb");
        println!(" *     *       *   8     8      8  d     d  b     b");
        println!(" *     *       *   8     8      8  d     d  b     b");
        println!(" *     *       *   8     8      8  ddddddd  bbbbbbb");
        println!("MMDB 0.1.0 SERVER IS RUNNING");
        println!("Martics Mem DataBase Server - MIT License");
        println!("               Quantum 2023");
        init()
    }

    /// Force transport safe raw pointer between threads
    pub struct unsafe_cell<T> {
        in_cell: T,
    }
    unsafe impl Send for unsafe_cell<*mut TcpStream> {}
    unsafe impl Send for unsafe_cell<*mut HashMap<String, String>> {}

    ///Threads transporting protocol
    pub enum messageprotocol {
        Shutdown,
        Connection(unsafe_cell<*mut TcpStream>),
    }

    /// Crypt data
    /// ### Examples
    /// ```
    /// use MMDB_Server::crypt;
    /// let x = crypt("547689uihgvfdtr678u9iokjhguyft7890-opkjhguyfr67t89u0iojkbhvcgdre56789uojhiguyftdre5r6789uijhbvgcdtre56t789uojhgyfrtyihv".into(),"5r6t78u9ijhgyftdr5678uijhugyftdre5r678uijhuyvftdr5678u9ijhugyftde5r678uihugftr67y8uijhgvftr67y8uijhg".into());
    /// ```
    pub fn crypt(m: String, key: String) -> String {
        //return m;
        let u8m = m.as_bytes();
        let mut u8k = key.as_bytes().into_iter();
        let u8k_ = u8k.clone();
        let mut u8o = Vec::new();
        for i in u8m {
            if u8k.clone().next() == None {
                u8k = u8k_.clone();
            }
            u8o.push(i.wrapping_add(
                *(u8k.next().unwrap_or_else(|| {
                    let m_ = m.clone();
                    eprintln!("Fatal:Failed to crypt string!{m_}");
                    let m_ = m.clone();
                    std::process::Command::new("echo")
                        .arg(m.clone())
                        .arg("> badcrypt")
                        .spawn();
                    std::process::exit(-1);
                    &0
                })),
            ));
        }
        let mut o = String::new();
        for i in u8o {
            o = o + i.to_string().as_str();
            o = o + "E"
        }
        o = o[0..(o.len() - 1)].to_string();
        return o;
    }

    /// Decrypt data
    /// ## Examples
    /// ```
    /// use MMDB_Server::decrypt;
    /// let x = decrypt("8E92E34E22E72E90E20E37E9".into(),"5678uijbvgftr678u9ijhgftr65789uijhugf".into());
    /// ```
    /// ### Fails
    /// * Unlegit crypted seq
    pub fn decrypt(m: String, key: String) -> String {
        //return m;
        let u8m = m.split('E');
        let mut u8k = key.as_bytes().into_iter();
        let u8k_ = u8k.clone();
        let mut u8o = Vec::new();
        for i in u8m {
            if u8k.clone().next() == None {
                u8k = u8k_.clone();
            }
            let i: u8 = i.trim().parse().unwrap_or_else(|_| {
                let m_ = m.clone();
                eprintln!("Fatal:Failed to decrypt data!{m_}");
                std::process::Command::new("echo")
                    .arg(m.clone())
                    .arg("> baddecrypt")
                    .spawn();
                std::process::exit(-1);
                0
            });
            u8o.push(i.wrapping_sub(
                *(u8k.next().unwrap_or_else(|| {
                    let m_ = m.clone();
                    eprintln!("Fatal:Failed to decrypt data!{m_}");
                    std::process::Command::new("echo")
                        .arg(m.clone())
                        .arg("> baddecrypt")
                        .spawn();
                    std::process::exit(-1);
                    &0
                })),
            ));
        }
        return String::from_utf8_lossy(&u8o.to_vec()).to_string();
    }

    impl messageprotocol {
        pub fn newstop() -> messageprotocol {
            messageprotocol::Shutdown
        }
        pub fn newconnection(stream: *mut TcpStream) -> messageprotocol {
            messageprotocol::Connection(unsafe_cell { in_cell: stream })
        }
    }

    #[derive(Debug, PartialEq)]
    pub struct Value {
        pub primary: String,
        pub attributes: Vec<String>,
    }

    #[derive(Debug, PartialEq)]
    pub struct OptionProperties {
        pub option: String,
        pub value: Value,
    }

    /// The main function of this server.
    /// Function run() call this to start server
    pub fn init() -> Result<(), Box<dyn Error>> {
        let mut args = env::args();
        let _ = args.next();
        let cfgdic = match args.next() {
            Some(cf) => cf,
            None => {
                println!("WARN:Config file not setted!Using default config file.");
                "./configs.mmdbcfg".into()
            }
        };
        let mut databases: HashMap<String, String> = HashMap::new();
        let mut configs = String::new();
        if let Ok(_tmp0) = fs::try_exists(cfgdic.clone()) {
            configs = fs::read_to_string(cfgdic.clone()).expect("Fatal:Cannot read config!");
        } else {
            eprintln!("Fatal:Config file not found!");
            process::exit(1);
        }
        let config_vec = configster::parse_file(cfgdic.as_str(), ',').unwrap_or_else(|_| {
            eprintln!("Fatal:Failed to load config!");
            std::process::exit(-1);
            Vec::<configster::OptionProperties>::new()
        });
        let mut dbdic = String::new();
        let mut configs: HashMap<String, String> = HashMap::new();
        for i in config_vec {
            configs.insert(i.option, i.value.primary);
        }
        dbdic = configs
            .get("DatabaseFile")
            .unwrap_or_else(|| {
                eprintln!("Fatal:Config file incorrect!");
                std::process::exit(-1);
                &String::new()
            })
            .to_string();
        match fs::try_exists(dbdic.clone()) {
            Ok(true) => {}
            Err(_) | Ok(false) => {
                fs::File::create(dbdic.clone());
            }
        }
        let db = fs::read_to_string(dbdic.clone().as_str()).unwrap();
        let dbv = db.split('P');
        for i in dbv {
            databases.insert(
                decrypt(
                    i.split('V').clone().collect::<Vec<&str>>()[0].to_string(),
                    configs.get("PASSWORD").unwrap().to_string(),
                ),
                decrypt(
                    i.split('V').collect::<Vec<&str>>()[1].to_string(),
                    configs.get("PASSWORD").unwrap().to_string(),
                ),
            );
        }

        if true {
            databases.insert(
                "PASSWORD".into(),
                "MMDB/0.1.0/CLIENT PASSWORD -KEEP-ALIVE- /PASSWORD CRYPTED:".to_string()
                    + &crypt(configs.get("PASSWORD").unwrap().to_string(),"MMDB/0.1.0/DEFAULT PASSWORD CRYPTER -O4UHRWO3IT4UY4WOTIUEHRILEUDSD-  /DEFAULT/".to_string()),
            );
        }

        let listener = TcpListener::bind("0.0.0.0:2274")?;

        let threadpool = ThreadPool::new(
            (i64::try_from(configs.get("MaxThreads").unwrap().parse::<i64>().unwrap()).unwrap())
                as usize,
        );

        let mut key = configs.get("PASSWORD").unwrap().to_string();

        let (send, receive) = std::sync::mpsc::channel::<messageprotocol>();
        let receiver_ = Arc::new(Mutex::new(receive));
        let databases_ = Arc::new(Mutex::new(unsafe_cell {
            in_cell: core::ptr::addr_of_mut!(databases),
        }));

        if *(configs.get("InfniteThreads").unwrap()) == "false".to_string() {
            for id in 1..(i64::try_from(configs.get("MaxThreads").unwrap().parse::<i64>().unwrap())
                .unwrap())
            {
                let receiver = receiver_.clone();
                let databases = databases_.clone();
                let dbd = dbdic.clone();
                let key_ = key.clone();
                threadpool.execute(move || {
                    loop {
                        match receiver.lock().unwrap().recv().unwrap() {
                            messageprotocol::Shutdown => {
                                println!("Worker {} was told to shutdown.Shuttingdown.",id);
                                break;
                            }
                            messageprotocol::Connection(stream_) => {
                                unsafe{
                                    let stream= stream_.in_cell;
                                    let mut reader = BufReader::new(&mut * stream);
                                    let mut writer = BufWriter::new(&mut * stream);
                                    let mut BUF = String::new();
                                    reader.read_to_string(&mut BUF);
                                    BUF = decrypt(BUF,((&mut * (&mut * databases.lock().unwrap()).in_cell).get("PASSWORD".into()).unwrap()).to_string());
                                    if BUF != "MMDB/0.1.0/CLIENT CONNECT -KEEP-ALIVE- /ASK FOR CONNECT" {continue;}
                                    writer.write_all(crypt("MMDB/0.1.0/SERVER ACCEPT -KEEP-ALIVE- /ACCEPT CONNECT -HEADER- /ASK FOR PASSWORD".to_string(),((&mut * (&mut * databases.lock().unwrap()).in_cell).get("PASSWORD".into()).unwrap()).to_string()).as_bytes());
                                    writer.flush();
                                    reader.read_to_string(&mut BUF);
                                    BUF = decrypt(BUF,((&mut * (&mut * databases.lock().unwrap()).in_cell).get("PASSWORD".into()).unwrap()).to_string());
                                    if BUF.starts_with("MMDB/0.1.0/CLIENT PASSWORD -KEEP-ALIVE- /PASSWORD CRYPTED:") {
                                        if BUF == (&mut * (&mut * databases.lock().unwrap()).in_cell).get("PASSWORD").unwrap().to_string() {
                                            writer.write_all(crypt("MMDB/0.1.0/SERVER ACCEPT -KEEP-ALIVE- /ACCEPT VERIFY -HEADER- /".to_string(),((&mut * (&mut * databases.lock().unwrap()).in_cell).get("PASSWORD".into()).unwrap()).to_string()).as_bytes());
                                            writer.flush(); 
                                        }
                                        else{
                                            writer.write_all(crypt("MMDB/0.1.0/SERVER FORBIDDEN -TERMINATE- /STOP..WRONG_PASSWORD".to_string(),((&mut * (&mut * databases.lock().unwrap()).in_cell).get("PASSWORD".into()).unwrap()).to_string()).as_bytes());
                                            writer.flush();
                                            continue;
                                        }
                                    }
                                    else{
                                        writer.write_all(crypt("MMDB/0.1.0/SERVER FORBIDDEN -TERMINATE- /STOP..UNVERIFIED_CONNECTION".to_string(),((&mut * (&mut * databases.lock().unwrap()).in_cell).get("PASSWORD".into()).unwrap()).to_string()).as_bytes());
                                        writer.flush();
                                        continue;
                                    }
                                    loop {
                                        reader.read_to_string(&mut BUF);
                                        BUF = decrypt(BUF,((&mut * (&mut * databases.lock().unwrap()).in_cell).get("PASSWORD".into()).unwrap()).to_string());
                                        if BUF.starts_with("MMDB/0.1.0/CLIENT GET -KEEP-ALIVE- /ASK FOR VAL..KEY:") {
                                            let mut iter = BUF.split(':');
                                            let _ = iter.next();
                                            match (&mut * (&mut * databases.lock().unwrap()).in_cell).get(iter.next().unwrap()) {
                                                Some(res) => {
                                                    writer.write_all(crypt((format!("MMDB/0.1.0/SERVER ACCEPT -KEEP-ALIVE- /ANS FOR ASKING VAL..VAL:{}",res)).to_string(),((&mut * (&mut * databases.lock().unwrap()).in_cell).get("PASSWORD".into()).unwrap()).to_string()).as_bytes());
                                                    writer.flush();
                                                }
                                                None => {
                                                    writer.write_all(crypt("MMDB/0.1.0/SERVER NOT FOUND -KEEP-ALIVE- /ANS FOR ASKING VAL..NOT FOUND".to_string(),((&mut * (&mut * databases.lock().unwrap()).in_cell).get("PASSWORD".into()).unwrap()).to_string()).as_bytes());
                                                    writer.flush();
                                                }
                                            }
                                        }
                                        else if BUF.starts_with("MMDB/0.1.0/CLIENT/SET -KEEP-ALIVE- /SET KV PAIR..KV PAIR:") {
                                            let mut iter1 = BUF.split(':');
                                            let _ = iter1.next();
                                            let mut iter2 = iter1.next().unwrap().split(';');
                                            if (&mut * (&mut * databases.lock().unwrap()).in_cell).contains_key(iter2.clone().next().unwrap()) {
                                                let mut v = (&mut * (&mut * databases.lock().unwrap()).in_cell).get(iter2.clone().next().unwrap()).unwrap();
                                                let _ = iter2.next();
                                                v = &iter2.next().unwrap().to_string();
                                            }
                                            else{
                                                (&mut * (&mut * databases.lock().unwrap()).in_cell).insert(iter2.next().unwrap().to_string(),iter2.next().unwrap().to_string());
                                            }
                                            writer.write_all(crypt("MMDB/0.1.0/SERVER ACCEPT -KEEP-ALIVE- /ANSWER FOR ASKING SET KV PAIRS..OK".to_string(),((&mut * (&mut * databases.lock().unwrap()).in_cell).get("PASSWORD".into()).unwrap()).to_string()).as_bytes());
                                            writer.flush();
                                        }
                                        else if BUF.starts_with("MMDB/0.1.0/CLIENT DISCONNECT -KEEP-ALIVE- /DISCONNECT") {
                                            writer.write_all(crypt("MMDB/0.1.0/SERVER DISCONNECT -DISCONNECT- /DISCONNECT".to_string(),((&mut * (&mut * databases.lock().unwrap()).in_cell).get("PASSWORD".into()).unwrap()).to_string()).as_bytes());
                                            writer.flush();
                                            break;
                                        }
                                        else if BUF.starts_with("MMDB/0.1.0/CLIENT -KEEP-ALIVE- /SAVE") {
                                            fs::remove_file(dbd.clone());
                                            let mut contents = String::new();
                                            for i in &mut * (&mut * databases.lock().unwrap()).in_cell {
                                                let (k,v) = i;
                                                contents += (crypt((*k).clone(),key_.clone()) + ("V") + crypt(v.to_string().clone(),key_.clone()).as_str() + "P").as_str();
                                            }
                                            contents = contents.to_string()[0..contents.len() - 1].to_string();
                                            fs::write(dbd.clone(), contents);
                                            writer.write_all("MMDB/0.1.0/SERVER ACCEPT -KEEP-ALIVE- /ANSWER FOR SAVING BATABASES..OK".as_bytes());
                                            writer.flush();
                                        }
                                        else {
                                            writer.write_all(crypt("MMDB/0.1.0/SERVER DISCONNECT -DISCONNECT- /UNABLE TO PARSE CONNECTION".to_string(),((&mut * (&mut * databases.lock().unwrap()).in_cell).get("PASSWORD".into()).unwrap()).to_string()).as_bytes());
                                            writer.flush();
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                });
            }
        }

        loop {
            if let Ok((mut stream, _)) = listener.accept() {
                send.send(messageprotocol::Connection(unsafe_cell {
                    in_cell: core::ptr::addr_of_mut!(stream),
                }))
                .unwrap();
            }
        }

        for _i in vec![0; 500] {
            send.send(messageprotocol::Shutdown).unwrap();
        }

        Ok(())
    }
}
