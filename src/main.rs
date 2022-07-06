use ipnet::Ipv4Net;
use std::net::Ipv4Addr;
use std::collections::{BTreeMap, HashMap};
use futures::executor::block_on;
use rand::Rng;
use std::time::{Duration, Instant};
use std::thread::sleep;

#[derive(Debug,PartialEq,Hash,Eq)]
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
            src_mask: as_u32_be(&src_net.network().octets()),
            src_port,
            dst_net: as_u32_be(&dst_net.addr().octets()),
            dst_mask: as_u32_be(&dst_net.network().octets()),
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
    src_map: BTreeMap<u8, HashMap<(u32,u16), bool>>,
    dst_map: BTreeMap<u8, HashMap<(u32,u16), bool>>,
    flow_map: HashMap<(u32, u16, u32, u16), Action>,
}

impl FlowTable {
    fn new() -> Self {
        Self {  
            src_map: BTreeMap::new(),
            dst_map: BTreeMap::new(),
            flow_map: HashMap::new(),
        }
    }
    fn add_flow(&mut self, flow: Flow){
        let src_mask: u8;
        if flow.src_mask == 0 {
            src_mask = 32;
        } else {
            src_mask = 32 - ((4294967295 - flow.src_mask + 1) as f32).log2() as u8;
        }
        let res = self.src_map.get_mut(&src_mask);
        match res {
            Some(map) => {
                map.insert((flow.src_net, flow.src_port), true);
            },
            None => {
                let mut map = HashMap::new();
                map.insert((flow.src_net, flow.src_port), true);
                self.src_map.insert(src_mask, map);
            },
        }

        let dst_mask: u8;
        if flow.dst_mask == 0 {
            dst_mask = 32;
        } else {
            dst_mask = 32 - ((4294967295 - flow.dst_mask + 1) as f32).log2() as u8;
        }
        let res = self.dst_map.get_mut(&dst_mask);
        match res {
            Some(map) => {
                map.insert((flow.dst_net, flow.dst_port), true);
            },
            None => {
                let mut map = HashMap::new();
                map.insert((flow.dst_net, flow.dst_port), true);
                self.dst_map.insert(dst_mask, map);
            },
        }
        self.flow_map.insert((flow.src_net, flow.src_port, flow.dst_net, flow.dst_port), flow.action);

    }

    async fn match_flow(&mut self, packet: Packet) -> Option<&Action>{
        let src_net_fut = get_net_port(packet.src_ip, packet.src_port, self.src_map.clone());
        let dst_net_fut = get_net_port(packet.dst_ip, packet.dst_port, self.dst_map.clone());

        let (src_net, dst_net) = futures::future::join(src_net_fut, dst_net_fut).await;

        if src_net.is_some() && dst_net.is_some(){
            let (src_net, src_port) = src_net.unwrap();
            let (dst_net, dst_port) = dst_net.unwrap();
            let res = self.flow_map.get(&(src_net, src_port, dst_net, dst_port));
            return res.clone()
        }

        let src_net_fut = get_net_port(packet.src_ip, 0, self.src_map.clone());
        let dst_net_fut = get_net_port(packet.dst_ip, packet.dst_port, self.dst_map.clone());

        let (src_net, dst_net) = futures::future::join(src_net_fut, dst_net_fut).await;

        if src_net.is_some() && dst_net.is_some(){
            let (src_net, src_port) = src_net.unwrap();
            let (dst_net, dst_port) = dst_net.unwrap();
            let res = self.flow_map.get(&(src_net, src_port, dst_net, dst_port));
            return res.clone()
        }

        let src_net_fut = get_net_port(packet.src_ip, packet.src_port, self.src_map.clone());
        let dst_net_fut = get_net_port(packet.dst_ip, 0, self.dst_map.clone());

        let (src_net, dst_net) = futures::future::join(src_net_fut, dst_net_fut).await;

        if src_net.is_some() && dst_net.is_some(){
            let (src_net, src_port) = src_net.unwrap();
            let (dst_net, dst_port) = dst_net.unwrap();
            let res = self.flow_map.get(&(src_net, src_port, dst_net, dst_port));
            return res.clone()
        }

        let src_net_fut = get_net_port(packet.src_ip, 0, self.src_map.clone());
        let dst_net_fut = get_net_port(packet.dst_ip, 0, self.dst_map.clone());

        let (src_net, dst_net) = futures::future::join(src_net_fut, dst_net_fut).await;

        if src_net.is_some() && dst_net.is_some(){
            let (src_net, src_port) = src_net.unwrap();
            let (dst_net, dst_port) = dst_net.unwrap();
            let res = self.flow_map.get(&(src_net, src_port, dst_net, dst_port));
            return res.clone()
        }
        None
    }
}

async fn get_net_port(ip: u32, port: u16, map: BTreeMap<u8, HashMap<(u32,u16), bool>>) -> Option<(u32,u16)>{
    for (mask, map) in map.clone() {
        let bin = ip;
        let base: u32 = 2;
        let max_mask_bin = 4294967295;
        let mask_bin: u32;
        if mask == 32 {
            mask_bin = 32;
        } else {
            mask_bin = max_mask_bin - (base.pow(mask as u32) - 1);
        }
        let masked: u32 = bin & mask_bin;
        let kv = map.get_key_value(&(masked, port));
        match kv {
            Some((k,_)) => { return Some(k.clone()) },
            None => { },
        }
    }
    None
}

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

fn flow_entry_generator(count: usize, mask_range: (u8, u8), src_port_range: (u16, u16), dst_port_range: (u16, u16)) -> (Vec<(Ipv4Net, u16, Ipv4Net, u16)>, Vec<Flow>){
    let mut rng = rand::thread_rng();
    let mut flow_list = Vec::new();
    let mut network_list = Vec::new();
    for _ in 1..count {

        let octet_1: u8 = rng.gen_range(1..254);
        let octet_2: u8 = rng.gen_range(0..254);
        let octet_3: u8 = rng.gen_range(0..254);
        let octet_4: u8 = rng.gen_range(0..254);
        let mask = rng.gen_range(mask_range.0..mask_range.1);
        let src_net = Ipv4Net::new(Ipv4Addr::new(octet_1, octet_2, octet_3, octet_4), mask).unwrap();

        let octet_1: u8 = rng.gen_range(1..254);
        let octet_2: u8 = rng.gen_range(0..254);
        let octet_3: u8 = rng.gen_range(0..254);
        let octet_4: u8 = rng.gen_range(0..254);
        let mask = rng.gen_range(mask_range.0..mask_range.1);
        let dst_net = Ipv4Net::new(Ipv4Addr::new(octet_1, octet_2, octet_3, octet_4), mask).unwrap();


        let action_gen: u8 = rng.gen_range(0..1);
        let action: Action;
        if action_gen == 0 {
            action = Action::Allow("foo".into());
        } else {
            action = Action::Deny;
        }
        let src_port = rng.gen_range(src_port_range.0..src_port_range.1);
        let dst_port = rng.gen_range(dst_port_range.0..dst_port_range.1);
        let flow = Flow::new(src_net, src_port, dst_net, dst_port, action);

        flow_list.push(flow);
        network_list.push((src_net, src_port, dst_net, dst_port));
    }
    (network_list, flow_list)
}

fn packet_generator(count: usize, network_list: Vec<(Ipv4Net, u16, Ipv4Net, u16)>) -> Vec<Packet>{

    let mut packet_list = Vec::new();
    let mut rng = rand::thread_rng();
    for _ in 0..count{
        let random_net = rng.gen_range(0..network_list.len());
        let (src_net, src_port, dst_net, dst_port) = network_list[random_net];
        let src_hosts = src_net.hosts().collect::<Vec<Ipv4Addr>>();
        let dst_hosts = dst_net.hosts().collect::<Vec<Ipv4Addr>>();
        let random_src = rng.gen_range(0..src_hosts.len());
        let random_dst = rng.gen_range(0..dst_hosts.len());
        let src_host = src_hosts[random_src];
        let dst_host = dst_hosts[random_dst];
        let packet = Packet::new(src_host, src_port, dst_host, dst_port);
        packet_list.push(packet);
    }
    packet_list
}

fn main() {

    let now = Instant::now();
    let (network_list, flow_list) = flow_entry_generator(10, (20,30), (80, 200), (200, 300));
    let packet_list = packet_generator(1000000, network_list);
    println!("generate time {:?}", now.elapsed());

    let mut flow_table = FlowTable::new();

    for flow in flow_list{
        flow_table.add_flow(flow);
    }

    let mut result_list = Vec::new();

    let now = Instant::now();
    for packet in packet_list {
        let mut flow_table = flow_table.clone();
        let res = flow_table.match_flow(packet);
        let res = block_on(res);
        result_list.push(res.cloned());
    }
    println!("match time {:?}", now.elapsed());

    /* 
    flow_table.add_flow(Flow::new("1.0.0.0/24".parse().unwrap(),
        0,
        "2.0.0.0/24".parse().unwrap(),
        80,
        Action::Allow("int1".into())
    ));
    

    
    let packet = Packet::new("1.0.0.1".parse().unwrap(), 0, "2.0.0.1".parse().unwrap(), 80);
    let res = flow_table.match_flow(packet);
    let res = block_on(res);
    assert_eq!(Some(&Action::Allow("int1".into())),res);
    println!("{:?}", res);

    
    let packet = Packet::new("1.1.1.1".parse().unwrap(), 0, "2.0.0.1".parse().unwrap(), 80);
    let res = flow_table.match_flow(packet);
    let res = block_on(res);
    assert_eq!(None,res);
    println!("{:?}", res);
    
    

    flow_table.add_flow(Flow::new("1.0.0.0/25".parse().unwrap(),
        0,
        "2.0.0.0/24".parse().unwrap(),
        80,
        Action::Allow("int2".into())
    ));

    
    flow_table.add_flow(Flow::new("1.1.1.0/24".parse().unwrap(),
        0,
        "2.0.0.0/24".parse().unwrap(),
        80,
        Action::Allow("int3".into())
    ));
    
    flow_table.add_flow(Flow::new("0.0.0.0/0".parse().unwrap(),
        0,
        "0.0.0.0/0".parse().unwrap(),
        81,
        Action::Deny
    ));
 
    flow_table.add_flow(Flow::new("0.0.0.0/0".parse().unwrap(),
        0,
        "0.0.0.0/0".parse().unwrap(),
        0,
        Action::Allow("int5".into())
    ));
    
     
    let packet = Packet::new("1.1.1.1".parse().unwrap(), 0, "2.0.0.1".parse().unwrap(), 80);
    let res = flow_table.match_flow(packet);
    let res = block_on(res);
    assert_eq!(Some(&Action::Allow("int3".into())),res);
    println!("{:?}", res);
    

    let packet = Packet::new("1.2.3.4".parse().unwrap(), 80, "5.6.7.8".parse().unwrap(), 80);
    let res = flow_table.match_flow(packet);
    let res = block_on(res);
    assert_eq!(Some(&Action::Allow("int5".into())),res);
    println!("{:?}", res);

    let packet = Packet::new("1.0.0.4".parse().unwrap(), 80, "5.6.7.8".parse().unwrap(), 81);
    let res = flow_table.match_flow(packet);
    let res = block_on(res);
    assert_eq!(Some(&Action::Deny),res);
    println!("{:?}", res);
    */

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

