use ipnet::Ipv4Net;
use std::net::Ipv4Addr;
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;
use std::time::Instant;

#[derive(Debug,PartialEq,Hash,Eq, Clone)]
struct Flow {
    src_net: u32,
    src_mask: u32,
    dst_net: u32,
    dst_mask: u32,
    src_port: u16,
    dst_port: u16,
    action: Action,
}

impl Flow{
    fn new(src_net: Ipv4Net, src_port: u16, dst_net: Ipv4Net, dst_port: u16, action: Action) -> Self {
        Self {  
            src_net: as_u32_be(&src_net.addr().octets()),
            src_mask: as_u32_be(&src_net.netmask().octets()),
            src_port,
            dst_net: as_u32_be(&dst_net.addr().octets()),
            dst_mask: as_u32_be(&dst_net.netmask().octets()),
            dst_port,
            action,
        }
    }
}

#[derive(Debug,PartialEq,Hash,Eq, Clone)]
enum Action {
    Deny,
    Allow(String)
}

#[derive(Debug,Clone)]
struct FlowTable{
    src_map: Rc<BTreeMap<u32, HashMap<(u32,u16), bool>>>,
    dst_map: Rc<BTreeMap<u32, HashMap<(u32,u16), bool>>>,
    flow_map: Rc<HashMap<(u32, u16, u32, u16), Action>>,
}

impl FlowTable {
    fn new() -> Self {
        Self {  
            src_map: Rc::new(BTreeMap::new()),
            dst_map: Rc::new(BTreeMap::new()),
            flow_map: Rc::new(HashMap::new()),
        }
    }
    fn add_flow(&mut self, flow: Flow){
        let src_mask = 4294967295 - flow.src_mask;
        let src_map = Rc::get_mut(&mut self.src_map).unwrap(); 
        let res = src_map.get_mut(&src_mask);
        match res {
            Some(map) => {
                map.insert((flow.src_net, flow.src_port), true);
            },
            None => {
                let mut map = HashMap::new();
                map.insert((flow.src_net, flow.src_port), true);
                src_map.insert(src_mask, map);
            },
        }

        let dst_mask = 4294967295 - flow.dst_mask;
        let dst_map = Rc::get_mut(&mut self.dst_map).unwrap(); 
        let res = dst_map.get_mut(&dst_mask);
        match res {
            Some(map) => {
                map.insert((flow.dst_net, flow.dst_port), true);
            },
            None => {
                let mut map = HashMap::new();
                map.insert((flow.dst_net, flow.dst_port), true);
                dst_map.insert(dst_mask, map);
            },
        }
        let flow_map = Rc::get_mut(&mut self.flow_map).unwrap(); 
        flow_map.insert((flow.src_net, flow.src_port, flow.dst_net, flow.dst_port), flow.action);

    }

    fn match_flow(&mut self, packet: Packet) -> Option<Action>{
        
        // match specific src/dst port first
        let src_net_specific = get_net_port(packet.src_ip, packet.src_port, self.src_map.clone());
        let dst_net_specific = get_net_port(packet.dst_ip, packet.dst_port, self.dst_map.clone());
        if src_net_specific.is_some() && dst_net_specific.is_some(){
            let (src_net, src_port) = src_net_specific.unwrap();
            let (dst_net, dst_port) = dst_net_specific.unwrap();
            let res = self.flow_map.get(&(src_net, src_port, dst_net, dst_port));
            return res.cloned()
        }

        // match specific src_port and 0 dst_port
        let src_net_0 = get_net_port(packet.src_ip, 0, self.src_map.clone());
        if src_net_0.is_some() && dst_net_specific.is_some(){
            let (src_net, src_port) = src_net_0.unwrap();
            let (dst_net, dst_port) = dst_net_specific.unwrap();
            let res = self.flow_map.get(&(src_net, src_port, dst_net, dst_port));
            return res.cloned()
        }

        // match 0 src_port and specific dst_port
        let dst_net_0 = get_net_port(packet.dst_ip, 0, self.dst_map.clone());
        if src_net_specific.is_some() && dst_net_0.is_some(){
            let (src_net, src_port) = src_net_specific.unwrap();
            let (dst_net, dst_port) = dst_net_0.unwrap();
            let res = self.flow_map.get(&(src_net, src_port, dst_net, dst_port));
            return res.cloned()
        }

        // match 0 src_port and 0 dst_port
        if src_net_0.is_some() && dst_net_0.is_some(){
            let (src_net, src_port) = src_net_0.unwrap();
            let (dst_net, dst_port) = dst_net_0.unwrap();
            let res = self.flow_map.get(&(src_net, src_port, dst_net, dst_port));
            return res.cloned()
        }
        None
    }
}

fn get_net_port(ip: u32, port: u16, map: Rc<BTreeMap<u32, HashMap<(u32,u16), bool>>>) -> Option<(u32,u16)>{
    for (mask, map) in map.as_ref() {
        let mask_bin = 4294967295 - mask;
        let masked: u32 = ip & mask_bin;
        let kv = map.get_key_value(&(masked, port));
        match kv {
            Some((k,_)) => { return Some(k.clone()) },
            None => { },
        }
    }
    None
}

#[derive(Debug, Clone)]
struct Packet {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
}

impl Packet {
    fn new(src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16) -> Self{
        Self { 
            src_ip: as_u32_be(&src_ip.octets()),
            src_port,
            dst_ip: as_u32_be(&dst_ip.octets()),
            dst_port,
        }
    }
}

fn main() {

    let mut flow_table = FlowTable::new();

    flow_table.add_flow(Flow::new("1.0.0.0/25".parse().unwrap(),
        0,
        "2.0.0.0/25".parse().unwrap(),
        80,
        Action::Allow("int1".into())
    ));
    
    let packet = Packet::new("1.0.0.1".parse().unwrap(), 0, "2.0.0.1".parse().unwrap(), 80);

    let now = Instant::now();
    for _ in 0..1000000{
        let res = flow_table.match_flow(packet.clone());
        let res = res;
        assert_eq!(Some(Action::Allow("int1".into())),res);
    }
    println!("1st stage lookup {:?}", now.elapsed());


    flow_table.add_flow(Flow::new("3.0.0.0/24".parse().unwrap(),
        0,
        "4.0.0.0/24".parse().unwrap(),
        80,
        Action::Allow("int2".into())
    ));
    
    let packet = Packet::new("3.0.0.1".parse().unwrap(), 0, "4.0.0.1".parse().unwrap(), 80);
    
    let now = Instant::now();
    for _ in 0..1000000{
        let res = flow_table.match_flow(packet.clone());
        let res = res;
        assert_eq!(Some(Action::Allow("int2".into())),res);
    }
    println!("2nd stage lookup {:?}", now.elapsed());



    flow_table.add_flow(Flow::new("5.0.0.0/23".parse().unwrap(),
        0,
        "6.0.0.0/23".parse().unwrap(),
        80,
        Action::Allow("int3".into())
    ));
    
    let packet = Packet::new("5.0.0.1".parse().unwrap(), 0, "6.0.0.1".parse().unwrap(), 80);

    let now = Instant::now();
    for _ in 0..1000000{
        let res = flow_table.match_flow(packet.clone());
        let res = res;
        assert_eq!(Some(Action::Allow("int3".into())),res);
    }
    println!("3rd stage lookup {:?}", now.elapsed());


    flow_table.add_flow(Flow::new("0.0.0.0/0".parse().unwrap(),
        0,
        "0.0.0.0/0".parse().unwrap(),
        0,
        Action::Allow("int4".into())
    ));
    
     
    let packet = Packet::new("1.2.3.5".parse().unwrap(), 0, "5.6.7.8".parse().unwrap(), 80);
    let now = Instant::now();
    for _ in 0..1000000{
        let res = flow_table.match_flow(packet.clone());
        let res = res;
        assert_eq!(Some(Action::Allow("int4".into())),res);
    }
    println!("4th stage lookup {:?}", now.elapsed());


}

fn as_br(x: u32) -> [u8; 4]{
    x.to_be_bytes()
}

fn as_u32_be(array: &[u8;4]) -> u32 {
    ((array[0] as u32) << 24) +
    ((array[1] as u32) << 16) +
    ((array[2] as u32) << 8) +
    ((array[3] as u32) << 0)
}

