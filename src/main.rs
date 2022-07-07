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
    flow_map: Rc<HashMap<(u32, u32, u16, u32, u32, u16), Action>>,
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
        flow_map.insert((flow.src_net, flow.src_mask, flow.src_port, flow.dst_net, flow.dst_mask, flow.dst_port), flow.action);

    }

    fn print(&mut self){
        let flow_map = Rc::get_mut(&mut self.flow_map).unwrap(); 
        for ((src_net, src_mask, src_port,dst_net, dst_mask, dst_port), action) in flow_map {
            let max_mask: u32 = 4294967295;
            let src_prefix_length: u32;
            if *src_mask == 0 {
                src_prefix_length = 0;
            } else {
                src_prefix_length = 32 - ((max_mask - *src_mask + 1) as f32).log2() as u32;
            }
            let dst_prefix_length: u32;
            if *dst_mask == 0 {
                dst_prefix_length = 0;
            } else {
                dst_prefix_length = 32 - ((max_mask - *dst_mask + 1) as f32).log2() as u32;
            }
            let octet = as_br(*src_net);
            let src = Ipv4Net::new(Ipv4Addr::new(octet[0], octet[1], octet[2], octet[3]), src_prefix_length as u8).unwrap();
            let octet = as_br(*dst_net);
            let dst = Ipv4Net::new(Ipv4Addr::new(octet[0], octet[1], octet[2], octet[3]), dst_prefix_length as u8).unwrap();
            println!("src: {:?}:{:?} dst: {:?}:{:?} -> {:?}", src, src_port, dst, dst_port, action);
        }
    }

    fn match_flow(&mut self, packet: Packet) -> Option<Action>{
        
        // match specific src/dst port first
        let src_net_specific = get_net_port(packet.src_ip, packet.src_port, self.src_map.clone());
        let dst_net_specific = get_net_port(packet.dst_ip, packet.dst_port, self.dst_map.clone());
        if src_net_specific.is_some() && dst_net_specific.is_some(){
            let (src_net, src_mask,  src_port) = src_net_specific.unwrap();
            let (dst_net, dst_mask, dst_port) = dst_net_specific.unwrap();
            let res = self.flow_map.get(&(src_net, src_mask, src_port, dst_net, dst_mask, dst_port));
            return res.cloned()
        }

        // match specific src_port and 0 dst_port
        let src_net_0 = get_net_port(packet.src_ip, 0, self.src_map.clone());
        if src_net_0.is_some() && dst_net_specific.is_some(){
            let (src_net, src_mask, src_port) = src_net_0.unwrap();
            let (dst_net, dst_mask, dst_port) = dst_net_specific.unwrap();
            let res = self.flow_map.get(&(src_net, src_mask, src_port, dst_net, dst_mask, dst_port));
            return res.cloned()
        }

        // match 0 src_port and specific dst_port
        let dst_net_0 = get_net_port(packet.dst_ip, 0, self.dst_map.clone());
        if src_net_specific.is_some() && dst_net_0.is_some(){
            let (src_net,src_mask, src_port) = src_net_specific.unwrap();
            let (dst_net,dst_mask, dst_port) = dst_net_0.unwrap();
            let res = self.flow_map.get(&(src_net, src_mask, src_port, dst_net, dst_mask, dst_port));
            return res.cloned()
        }

        // match 0 src_port and 0 dst_port
        if src_net_0.is_some() && dst_net_0.is_some(){
            let (src_net,src_mask, src_port) = src_net_0.unwrap();
            let (dst_net,dst_mask, dst_port) = dst_net_0.unwrap();
            let res = self.flow_map.get(&(src_net, src_mask, src_port, dst_net, dst_mask, dst_port));
            return res.cloned()
        }
        None
    }
}

fn get_net_port(ip: u32, port: u16, map: Rc<BTreeMap<u32, HashMap<(u32,u16), bool>>>) -> Option<(u32,u32,u16)>{
    for (mask, map) in map.as_ref() {
        let mask_bin = 4294967295 - mask;
        let masked: u32 = ip & mask_bin;
        let kv = map.get_key_value(&(masked, port));
        match kv {
            Some(((net, port),_)) => { return Some((net.clone(),mask_bin, port.clone())) },
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
        0,
        Action::Allow("int1".into())
    ));

    

    flow_table.add_flow(Flow::new("3.0.0.0/24".parse().unwrap(),
        0,
        "4.0.0.0/24".parse().unwrap(),
        0,
        Action::Allow("int2".into())
    ));

    flow_table.add_flow(Flow::new("5.0.0.0/23".parse().unwrap(),
        0,
        "6.0.0.0/23".parse().unwrap(),
        0,
        Action::Allow("int3".into())
    ));

    flow_table.add_flow(Flow::new("0.0.0.0/0".parse().unwrap(),
        0,
        "0.0.0.0/0".parse().unwrap(),
        0,
        Action::Allow("int4".into())
    ));
    println!("flow table:");
    flow_table.print();

    println!("1st stage lookups:");
    
    let packet = Packet::new("1.0.0.1".parse().unwrap(), 0, "2.0.0.1".parse().unwrap(), 0);

    let now = Instant::now();
    for _ in 0..1000000{
        let res = flow_table.match_flow(packet.clone());
        let res = res;
        assert_eq!(Some(Action::Allow("int1".into())),res);
    }
    println!("-- specific sport - specific dport {:?}", now.elapsed());

    let packet = Packet::new("1.0.0.1".parse().unwrap(), 80, "2.0.0.1".parse().unwrap(), 0);

    let now = Instant::now();
    for _ in 0..1000000{
        let res = flow_table.match_flow(packet.clone());
        let res = res;
        assert_eq!(Some(Action::Allow("int1".into())),res);
    }
    println!("-- wildcard sport - specific dport {:?}", now.elapsed());

    let packet = Packet::new("1.0.0.1".parse().unwrap(), 0, "2.0.0.1".parse().unwrap(), 80);

    let now = Instant::now();
    for _ in 0..1000000{
        let res = flow_table.match_flow(packet.clone());
        let res = res;
        assert_eq!(Some(Action::Allow("int1".into())),res);
    }
    println!("-- specific sport - wildcard dport {:?}", now.elapsed());

    let packet = Packet::new("1.0.0.1".parse().unwrap(), 80, "2.0.0.1".parse().unwrap(), 80);

    let now = Instant::now();
    for _ in 0..1000000{
        let res = flow_table.match_flow(packet.clone());
        let res = res;
        assert_eq!(Some(Action::Allow("int1".into())),res);
    }
    println!("-- specific sport - wildcard dport {:?}", now.elapsed());

    println!("2nd stage lookups:");
    
    let packet = Packet::new("3.0.0.1".parse().unwrap(), 0, "4.0.0.1".parse().unwrap(), 0);
    
    let now = Instant::now();
    for _ in 0..1000000{
        let res = flow_table.match_flow(packet.clone());
        let res = res;
        assert_eq!(Some(Action::Allow("int2".into())),res);
    }
    println!("-- specific sport - specific dport {:?}", now.elapsed());

    let packet = Packet::new("3.0.0.1".parse().unwrap(), 80, "4.0.0.1".parse().unwrap(), 0);
    
    let now = Instant::now();
    for _ in 0..1000000{
        let res = flow_table.match_flow(packet.clone());
        let res = res;
        assert_eq!(Some(Action::Allow("int2".into())),res);
    }
    println!("-- wildcard sport - specific dport {:?}", now.elapsed());

    let packet = Packet::new("3.0.0.1".parse().unwrap(), 0, "4.0.0.1".parse().unwrap(), 80);
    
    let now = Instant::now();
    for _ in 0..1000000{
        let res = flow_table.match_flow(packet.clone());
        let res = res;
        assert_eq!(Some(Action::Allow("int2".into())),res);
    }
    println!("-- specific sport - wildcard dport {:?}", now.elapsed());

    let packet = Packet::new("3.0.0.1".parse().unwrap(), 80, "4.0.0.1".parse().unwrap(), 80);
    
    let now = Instant::now();
    for _ in 0..1000000{
        let res = flow_table.match_flow(packet.clone());
        let res = res;
        assert_eq!(Some(Action::Allow("int2".into())),res);
    }
    println!("-- wildcard sport - wildcard dport {:?}", now.elapsed());

    println!("3rd stage lookups:");
    
    let packet = Packet::new("5.0.0.1".parse().unwrap(), 0, "6.0.0.1".parse().unwrap(), 0);

    let now = Instant::now();
    for _ in 0..1000000{
        let res = flow_table.match_flow(packet.clone());
        let res = res;
        assert_eq!(Some(Action::Allow("int3".into())),res);
    }
    println!("-- specific sport - specific dport {:?}", now.elapsed());

    let packet = Packet::new("5.0.0.1".parse().unwrap(), 80, "6.0.0.1".parse().unwrap(), 0);

    let now = Instant::now();
    for _ in 0..1000000{
        let res = flow_table.match_flow(packet.clone());
        let res = res;
        assert_eq!(Some(Action::Allow("int3".into())),res);
    }
    println!("-- wildcard sport - specific dport {:?}", now.elapsed());

    let packet = Packet::new("5.0.0.1".parse().unwrap(), 0, "6.0.0.1".parse().unwrap(), 80);

    let now = Instant::now();
    for _ in 0..1000000{
        let res = flow_table.match_flow(packet.clone());
        let res = res;
        assert_eq!(Some(Action::Allow("int3".into())),res);
    }
    println!("-- specific sport - wildcard dport {:?}", now.elapsed());

    let packet = Packet::new("5.0.0.1".parse().unwrap(), 80, "6.0.0.1".parse().unwrap(), 80);

    let now = Instant::now();
    for _ in 0..1000000{
        let res = flow_table.match_flow(packet.clone());
        let res = res;
        assert_eq!(Some(Action::Allow("int3".into())),res);
    }
    println!("-- wildcard sport - wildcard dport {:?}", now.elapsed());

    println!("4th stage lookups:");
     
    let packet = Packet::new("1.2.3.5".parse().unwrap(), 0, "5.6.7.8".parse().unwrap(), 0);
    let now = Instant::now();
    for _ in 0..1000000{
        let res = flow_table.match_flow(packet.clone());
        let res = res;
        assert_eq!(Some(Action::Allow("int4".into())),res);
    }
    println!("-- specific sport - specific dport {:?}", now.elapsed());

    let packet = Packet::new("1.2.3.5".parse().unwrap(), 80, "5.6.7.8".parse().unwrap(), 0);
    let now = Instant::now();
    for _ in 0..1000000{
        let res = flow_table.match_flow(packet.clone());
        let res = res;
        assert_eq!(Some(Action::Allow("int4".into())),res);
    }
    println!("-- wildcard sport - specific dport {:?}", now.elapsed());

    let packet = Packet::new("1.2.3.5".parse().unwrap(), 0, "5.6.7.8".parse().unwrap(), 80);
    let now = Instant::now();
    for _ in 0..1000000{
        let res = flow_table.match_flow(packet.clone());
        let res = res;
        assert_eq!(Some(Action::Allow("int4".into())),res);
    }
    println!("-- specific sport - wildcard dport {:?}", now.elapsed());

    let packet = Packet::new("1.2.3.5".parse().unwrap(), 80, "5.6.7.8".parse().unwrap(), 80);
    let now = Instant::now();
    for _ in 0..1000000{
        let res = flow_table.match_flow(packet.clone());
        let res = res;
        assert_eq!(Some(Action::Allow("int4".into())),res);
    }
    println!("-- wildcard sport - wildcard dport {:?}", now.elapsed());


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

