use std::thread;
use std::sync::{Arc, Mutex};

fn test(a : &Arc<Mutex<u8>>, c : u8 )
{
    *a.lock().unwrap() += 1;
    println!("{}", &c);
    
}

pub fn thread_test_fn()
{
    //let mut handles = vec![];
    //let counter = Arc::new(Mutex::new(0_u8));
//
    //for i in 0..10 {
    //    let counter = Arc::clone(&counter);
    //    //let handle = thread::spawn(test());
    //    
    //    handles.push(handle);
    //}
//
    //for handle in handles {
    //    handle.join().unwrap();
    //}
//
    //println!("Result: {}", *counter.lock().unwrap());
}