use ipnet::Ipv4Net;
use std::net::Ipv4Addr;
use std::collections::{BTreeMap, HashMap};
use futures::executor::block_on;


#[derive(Debug,PartialEq,Hash,Eq,Clone)]
struct NetPort{
    ipv4_net: Ipv4Net,
    port: u16,
}
#[derive(Debug,PartialEq,Hash,Eq)]
struct Flow {
    src_net: Ipv4Net,
    dst_net: Ipv4Net,
    src_port: u16,
    dst_port: u16,
    action: Action,
}

impl Flow{
    //fn new() -> Self {
    //    Self {  }
    //}
}

#[derive(Debug,PartialEq,Hash,Eq)]
enum Action {
    Deny, Allow
}
struct FlowTable{
    src_map: BTreeMap<u8, HashMap<NetPort, bool>>,
    dst_map: BTreeMap<u8, HashMap<NetPort, bool>>,
    flow_map: HashMap<(Ipv4Addr, u16, Ipv4Addr, u16), Action>,
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
        let src_net = flow.src_net;
        let src_mask = 32 - flow.src_net.prefix_len();
        let src_port = flow.src_port;
        let net_port = NetPort{
            ipv4_net: src_net,
            port: src_port,
        };
        let res = self.src_map.get_mut(&src_mask);
        match res {
            Some(map) => {
                map.insert(net_port, true);
            },
            None => {
                let mut map = HashMap::new();
                map.insert(net_port, true);
                self.src_map.insert(src_mask, map);
            },
        }

        let dst_net = flow.dst_net;
        let dst_netmask = 32 - flow.dst_net.prefix_len();
        let dst_port = flow.dst_port;
        let net_port = NetPort{
            ipv4_net: dst_net,
            port: dst_port,
        };
        let res = self.dst_map.get_mut(&dst_netmask);
        match res {
            Some(map) => {
                map.insert(net_port, true);
            },
            None => {
                let mut map = HashMap::new();
                map.insert(net_port, true);
                self.dst_map.insert(dst_netmask, map);
            },
        }
        self.flow_map.insert((flow.src_net.addr(), flow.src_port, flow.dst_net.addr(), flow.dst_port), flow.action);

    }

    async fn match_flow(&mut self, packet: Packet) -> Option<&Action>{
        let src_net_fut = get_net_port(packet.src_ip, packet.src_port, self.src_map.clone());
        let dst_net_fut = get_net_port(packet.dst_ip, packet.dst_port, self.dst_map.clone());

        let (src_net, dst_net) = futures::future::join(src_net_fut, dst_net_fut).await;

        if src_net.is_some() && dst_net.is_some(){
            let src = src_net.unwrap();
            let dst = dst_net.unwrap();
            let res = self.flow_map.get(&(src.ipv4_net.addr(), src.port, dst.ipv4_net.addr(), dst.port));
            return res.clone()
        }

        let src_net_fut = get_net_port(packet.src_ip, 0, self.src_map.clone());
        let dst_net_fut = get_net_port(packet.dst_ip, packet.dst_port, self.dst_map.clone());

        let (src_net, dst_net) = futures::future::join(src_net_fut, dst_net_fut).await;

        if src_net.is_some() && dst_net.is_some(){
            let src = src_net.unwrap();
            let dst = dst_net.unwrap();
            let res = self.flow_map.get(&(src.ipv4_net.addr(), src.port, dst.ipv4_net.addr(), dst.port));
            return res.clone()
        }

        let src_net_fut = get_net_port(packet.src_ip, packet.src_port, self.src_map.clone());
        let dst_net_fut = get_net_port(packet.dst_ip, 0, self.dst_map.clone());

        let (src_net, dst_net) = futures::future::join(src_net_fut, dst_net_fut).await;

        if src_net.is_some() && dst_net.is_some(){
            let src = src_net.unwrap();
            let dst = dst_net.unwrap();
            let res = self.flow_map.get(&(src.ipv4_net.addr(), src.port, dst.ipv4_net.addr(), dst.port));
            return res.clone()
        }

        let src_net_fut = get_net_port(packet.src_ip, 0, self.src_map.clone());
        let dst_net_fut = get_net_port(packet.dst_ip, 0, self.dst_map.clone());

        let (src_net, dst_net) = futures::future::join(src_net_fut, dst_net_fut).await;

        if src_net.is_some() && dst_net.is_some(){
            let src = src_net.unwrap();
            let dst = dst_net.unwrap();
            let res = self.flow_map.get(&(src.ipv4_net.addr(), src.port, dst.ipv4_net.addr(), dst.port));
            return res.clone()
        }
        None
    }
}

async fn get_net_port(ip: Ipv4Addr, port: u16, map: BTreeMap<u8, HashMap<NetPort, bool>>) -> Option<NetPort>{
    for (mask, map) in map.clone() {
        let map = map.clone();
        let octets = ip.octets();
        let bin = as_u32_be(&octets);
        let base: u32 = 2;
        let max_mask: Ipv4Addr = "255.255.255.255".parse().unwrap();
        let octets = max_mask.octets();
        let max_mask_bin = as_u32_be(&octets);
        let mask_bin: u32;
        if mask == 32 {
            mask_bin = 0;
        } else {
            mask_bin = max_mask_bin - (base.pow(mask as u32) - 1);
        }
        let masked: u32 = bin & mask_bin;
        let octets = as_br(masked);
        let masked_ip = Ipv4Addr::from(octets);
        let kv = map.get_key_value(&NetPort{
            ipv4_net: format!("{}/{}",masked_ip,32-mask).parse().unwrap(),
            port: port.clone(),
        });
        match kv {
            Some((k,_)) => { return Some(k.clone()) },
            None => { },
        }
    }
    None
}

struct Packet {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
}

impl Packet {
    fn new(src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16) -> Self{
        Self { 
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        }
    }
}

fn main() {

    let mut flow_table = FlowTable::new();

    flow_table.add_flow(Flow{
        src_net: "1.0.0.0/24".parse().unwrap(),
        src_port: 0,
        dst_net: "2.0.0.0/24".parse().unwrap(),
        dst_port: 80,
        action: Action::Allow,
    });

    let packet = Packet::new("1.0.0.1".parse().unwrap(), 0, "2.0.0.1".parse().unwrap(), 80);
    let res = flow_table.match_flow(packet);
    let res = block_on(res);
    println!("{:?}", res);

    let packet = Packet::new("1.1.1.1".parse().unwrap(), 0, "2.0.0.1".parse().unwrap(), 80);
    let res = flow_table.match_flow(packet);
    let res = block_on(res);
    println!("{:?}", res);

    flow_table.add_flow(Flow{
        src_net: "1.0.0.0/25".parse().unwrap(),
        src_port: 0,
        dst_net: "2.0.0.0/24".parse().unwrap(),
        dst_port: 80,
        action: Action::Deny,
    });

    flow_table.add_flow(Flow{
        src_net: "1.1.1.0/25".parse().unwrap(),
        src_port: 0,
        dst_net: "2.0.0.0/24".parse().unwrap(),
        dst_port: 80,
        action: Action::Allow,
    });

    flow_table.add_flow(Flow{
        src_net: "0.0.0.0/0".parse().unwrap(),
        src_port: 81,
        dst_net: "0.0.0.0/0".parse().unwrap(),
        dst_port: 0,
        action: Action::Allow,
    });

    let packet = Packet::new("1.0.0.1".parse().unwrap(), 0, "2.0.0.1".parse().unwrap(), 80);
    let res = flow_table.match_flow(packet);
    let res = block_on(res);
    println!("{:?}", res);

    let packet = Packet::new("1.1.1.1".parse().unwrap(), 0, "2.0.0.1".parse().unwrap(), 80);
    let res = flow_table.match_flow(packet);
    let res = block_on(res);
    println!("{:?}", res);

    let packet = Packet::new("1.2.3.4".parse().unwrap(), 80, "5.6.7.8".parse().unwrap(), 80);
    let res = flow_table.match_flow(packet);
    let res = block_on(res);
    println!("{:?}", res);

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

