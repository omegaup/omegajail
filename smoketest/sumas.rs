use std::io;

fn main() -> io::Result<()> {
    let mut line = String::new();

    io::stdin().read_line(&mut line)?;
    let mut sum: i64 = 0;
    for s in line.trim().split(" ") {
        sum += i64::from_str_radix(s, 10).unwrap();
    }
    println!("{}", sum);

    Ok(())
}
