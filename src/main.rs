use std;
use env_logger;
use clap::{App, Arg};
use rpassword;
use colored::*;

mod common;
mod masterkey;
mod sitekey;
mod templates;
mod identicon;

mod tests;

fn main() {
    let _ = env_logger::try_init();
    let matches = App::new("MPW password generator")
        .version("0.1.0")
        .author("Dario Goetz <dario.goetz@googlemail.com>")
        .about("Generates passwords using the masterpasswordapp algorithm")
        .arg(
            Arg::with_name("name")
                .index(1)
                .short("n")
                .long("full-name")
                .value_name("full_name")
                .help("Full name")
                .required(true),
        )
        .arg(
            Arg::with_name("site")
                .index(2)
                .short("s")
                .long("site-name")
                .value_name("site_name")
                .help("Name of site to generate password for"),
        )
        .arg(
            Arg::with_name("type")
                .short("t")
                .long("password-type")
                .value_name("pw_type")
                .default_value("Maximum")
                .help("Type of password")
                .possible_values(&["Maximum", "Long", "Medium", "Short", "Basic", "PIN", "Name", "Phrase"]),
        )
        .get_matches();

    let pw_type = match matches.value_of("type").unwrap() {
        "Maximum" => &common::PasswordType::MaximumSecurity,
        "Long" => &common::PasswordType::Long,
        "Medium" => &common::PasswordType::Medium,
        "Short" => &common::PasswordType::Short,
        "Basic" => &common::PasswordType::Basic,
        "PIN" => &common::PasswordType::PIN,
        "Name" => &common::PasswordType::Name,
        "Phrase" => &common::PasswordType::Phrase,
        _ => &common::PasswordType::MaximumSecurity,
    };
    let full_name = matches.value_of("name").unwrap();

    let password = rpassword::prompt_password_stdout("Master Password: ").unwrap();
    let id = identicon::generate(&full_name, &password);
    println!("Identity: {}", id.green());

    let mut one_shot = false;
    loop {
        let site_key = match matches.value_of("site") {
            Some(site_key) => {
                one_shot = true;

                site_key.to_string()
            },
            None => {
                println!("Please enter site name:");
                let mut site_key = String::new();
                std::io::stdin().read_line(&mut site_key)
                    .expect("Could not read site key.");

                site_key
            }
        };
        let site_key = site_key.trim();

        let purpose = common::Purpose::Authentication;
        let masterkey = masterkey::gen_masterkey(&password, &full_name, &purpose);
        let sitekey = sitekey::gen_sitekey(&masterkey, &site_key, &purpose, 1 as i32);
        if let Some(password) = templates::get_password(&sitekey, &pw_type) {
            println!("The password is: {}", password.green().bold());
        }
        if one_shot {
            break;
        } else {
            println!();
        }
    }
}
