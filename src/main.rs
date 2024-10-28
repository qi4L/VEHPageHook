use crate::veh_page_hook::veh_page_hook;

mod veh_page_hook;

const PAYLOAD: &str = include_str!("../io/msf_calc.txt");

fn main() {
    let qi:Vec<u8> = vec![];
    unsafe {
        veh_page_hook(qi);
    }
}