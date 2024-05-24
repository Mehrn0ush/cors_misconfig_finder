 /*!
 * CORS Misconfig Finder
 * Version: 1.0.0
 * Author: Mehrnoush. Mehrnoush.vaseghi@gmail.com | https://medium.com/@Mehrnoush | https://github.com/Mehrn0ush
 * Description: Detects CORS misconfigurations
 */

 use std::fs::File;
use std::io::Write;
use std::time::Duration;
use clap::{Arg, Command};
use colored::*;
use percent_encoding::percent_decode_str;
use reqwest::{self, header::{HeaderMap, HeaderValue, HeaderName}, Proxy};
use tokio::time::sleep;
use url::Url;
use regex::Regex;

fn validate_url(url: &str) -> Result<(), String> {
    Url::parse(url).map(|_| ()).map_err(|e| format!("Invalid URL: {}", e))
}

fn validate_headers(headers: &str) -> Result<(), String> {
    let re = Regex::new(r"^[a-zA-Z0-9-]+: .+$").unwrap();
    for line in headers.lines() {
        if !re.is_match(line) {
            return Err(format!("Invalid header format: {}", line));
        }
    }
    Ok(())
}

fn validate_cookie(cookie: &str) -> Result<(), String> {
    if cookie.contains('\n') {
        return Err("Cookie should not contain newline characters".to_string());
    }
    Ok(())
}

fn validate_proxy(proxy: &str) -> Result<(), String> {
    Url::parse(proxy).map(|_| ()).map_err(|e| format!("Invalid proxy URL: {}", e))
}

fn validate_rate_limit(rate_limit: &str) -> Result<u64, String> {
    rate_limit.parse::<u64>().map_err(|e| format!("Invalid rate limit: {}", e))
}

fn validate_method(method: &str) -> Result<(), String> {
    match method.to_uppercase().as_str() {
        "GET" | "POST" => Ok(()),
        _ => Err("Invalid HTTP method. Use GET or POST".to_string())
    }
}

async fn scan(url: &str, custom_headers: Option<&str>, cookie: Option<&str>, proxy: Option<&str>, output: Option<&str>, _silent: bool, no_color: bool, rate_limit: Option<u64>, method: &str, thirdparty: &String, invalid_origin: &String) {
    let url = percent_decode_str(url).decode_utf8_lossy().to_string();
    let parsed_url = match Url::parse(&url) {
        Ok(url) => url,
        Err(e) => {
            eprintln!("Error parsing URL: {}", e);
            return;
        }
    };
    let origin = match parsed_url.host_str() {
        Some(host) => host,
        None => {
            eprintln!("Error extracting host from URL");
            return;
        }
    };

    let reflected_origin = url.clone();
    let trusted_subdomains = format!("http://subdomain.{}", origin);
    let regex_bypass = format!("http://{}.attacker.com", origin);
    let null_origin = "null".to_string();
    let breaking_tls = format!("http://{}", origin);
    let advanced_regex_bypass = format!("http://{}.attacker.com", origin);
    let pre_domain_bypass = format!("http://attacker.com.{}", origin);
    let post_domain_bypass = format!("http://{}.attacker.com", origin);
    let backtick_bypass = format!("http://`{}`", origin);
    let unescaped_dot_bypass = format!("http://{}.com", origin);
    let underscore_bypass = format!("http://{}_com", origin);
    let wildcard_value = "*".to_string();
    let http_allowance_test = format!("http://{}", origin);

    let bypass_dict = vec![
        ("Reflected Origin", &reflected_origin),
        ("Trusted Subdomains", &trusted_subdomains),
        ("Regexp bypass", &regex_bypass),
        ("Null Origin", &null_origin),
        ("Breaking TLS", &breaking_tls),
        ("Advance Regexp bypass", &advanced_regex_bypass),
        ("Pre-domain Bypass", &pre_domain_bypass),
        ("Post-domain Bypass", &post_domain_bypass),
        ("Backtick Bypass", &backtick_bypass),
        ("Unescaped Dot Bypass", &unescaped_dot_bypass),
        ("Underscore Bypass", &underscore_bypass),
        ("Invalid Value", invalid_origin),
        ("Wildcard Value", &wildcard_value),
        ("Third-party Allowance Test", thirdparty),
        ("HTTP Allowance Test", &http_allowance_test),
    ];

    let mut request_headers = HeaderMap::new();
    request_headers.insert("User-Agent", HeaderValue::from_static("Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0"));
    request_headers.insert("Accept", HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"));

    if let Some(headers) = custom_headers {
        let headers_owned: Vec<String> = headers.replace("\\n", "\n").lines().map(|line| line.to_string()).collect();
        for header_line in headers_owned {
            let parts: Vec<&str> = header_line.splitn(2, ':').collect();
            if parts.len() == 2 {
                let header_name = match HeaderName::from_bytes(parts[0].trim().as_bytes()) {
                    Ok(name) => name,
                    Err(e) => {
                        eprintln!("Error parsing header name: {}", e);
                        continue;
                    }
                };
                let header_value = match HeaderValue::from_str(parts[1].trim()) {
                    Ok(value) => value,
                    Err(e) => {
                        eprintln!("Error parsing header value: {}", e);
                        continue;
                    }
                };
                request_headers.insert(header_name, header_value);
            }
        }
    }

    if let Some(cookie) = cookie {
        match HeaderValue::from_str(cookie) {
            Ok(value) => { request_headers.insert("Cookie", value); },
            Err(e) => {
                eprintln!("Error parsing cookie: {}", e);
                return;
            }
        }
    }

    let client = if let Some(proxy_url) = proxy {
        let proxy = match Proxy::all(proxy_url) {
            Ok(proxy) => proxy,
            Err(e) => {
                eprintln!("Error setting proxy: {}", e);
                return;
            }
        };
        match reqwest::Client::builder().proxy(proxy).build() {
            Ok(client) => client,
            Err(e) => {
                eprintln!("Error building client with proxy: {}", e);
                return;
            }
        }
    } else {
        reqwest::Client::new()
    };

    for (bypass_name, bypass_value) in &bypass_dict {
        request_headers.insert("Origin", HeaderValue::from_str(bypass_value).unwrap());
        let request = match method.to_lowercase().as_str() {
            "post" => match client.post(&url).headers(request_headers.clone()).build() {
                Ok(req) => req,
                Err(e) => {
                    eprintln!("Error building POST request: {}", e);
                    continue;
                }
            },
            _ => match client.get(&url).headers(request_headers.clone()).build() {
                Ok(req) => req,
                Err(e) => {
                    eprintln!("Error building GET request: {}", e);
                    continue;
                }
            }
        };

        let response = match client.execute(request).await {
            Ok(res) => res,
            Err(e) => {
                eprintln!("Error executing request: {}", e);
                continue;
            }
        };
        let status_code = response.status();
        let response_headers = response.headers();
        let acao = response_headers.get("Access-Control-Allow-Origin").map(|v| v.to_str().unwrap_or("")).unwrap_or("");
        let acac = response_headers.get("Access-Control-Allow-Credentials").map(|v| v.to_str().unwrap_or("")).unwrap_or("");

        println!("Testing with Origin: {}", bypass_value);
        println!("Response Status Code: {}", status_code);
        println!("Response Headers: {:?}", response_headers);
        println!("Access-Control-Allow-Origin: {}", acao);
        println!("Access-Control-Allow-Credentials: {}", acac);

        let status = if acao == *bypass_value && acac == "true" {
            "[Vulnerable]"
        } else if acao == *bypass_value {
            "[Potentially Vulnerable] (Reflected Origin but without credentials)"
        } else if acao == "" {
            "[Potentially Vulnerable] (Access-Control-Allow-Origin header is empty)"
        } else {
            "[Not Vulnerable]"
        };

        let result = format!("{} {} {}: {} (Status: {})\nAccess-Control-Allow-Origin: {}\nAccess-Control-Allow-Credentials: {}", status, bypass_name, bypass_value, url, status_code, acao, acac);

        if no_color {
            println!("{}", result);
        } else {
            if status.contains("[Vulnerable]") {
                println!("{}", result.red());
            } else if status.contains("[Potentially Vulnerable]") {
                println!("{}", result.yellow());
            } else {
                println!("{}", result.green());
            }
        }

        if let Some(delay) = rate_limit {
            sleep(Duration::from_millis(delay)).await;
        }

        if let Some(output_file) = output {
            match File::create(output_file) {
                Ok(mut file) => {
                    writeln!(file, "Vulnerability Check Complete").unwrap();
                    writeln!(file, "Testing with Origin: {}", bypass_value).unwrap();
                    writeln!(file, "Response Status Code: {}", status_code).unwrap();
                    writeln!(file, "Response Headers: {:?}", response_headers).unwrap();
                    writeln!(file, "Access-Control-Allow-Origin: {}", acao).unwrap();
                    writeln!(file, "Access-Control-Allow-Credentials: {}", acac).unwrap();
                    writeln!(file, "{} {} {}: {} (Status: {})\nAccess-Control-Allow-Origin: {}\nAccess-Control-Allow-Credentials: {}", status, bypass_name, bypass_value, url, status_code, acao, acac).unwrap();
                }
                Err(e) => {
                    eprintln!("Error writing to output file: {}", e);
                }
            }
        }
    }

    if let Some(output_file) = output {
        match File::create(output_file) {
            Ok(mut file) => {
                writeln!(file, "Vulnerability Check Complete").unwrap();
            }
            Err(e) => {
                eprintln!("Error creating output file: {}", e);
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let matches = Command::new("corsmis_confi_finder")
        .version("1.0.0")
        .about("Detects CORS misconfigurations")
        .arg(Arg::new("url")
            .index(1)
            .required(true)
            .help("Target URL to probe")
            .value_parser(clap::value_parser!(String)))
        .arg(Arg::new("custom_headers")
            .short('c')
            .long("custom-headers")
            .num_args(1)
            .help("Custom headers to include in the requests (format: 'Header1: value1\\nHeader2: value2')")
            .value_parser(clap::value_parser!(String)))
        .arg(Arg::new("cookie")
            .short('k')
            .long("cookie")
            .num_args(1)
            .help("Cookie to include in the requests")
            .value_parser(clap::value_parser!(String)))
        .arg(Arg::new("rate_limit")
            .short('r')
            .long("rate-limit")
            .num_args(1)
            .help("Rate limit between requests in milliseconds")
            .value_parser(clap::value_parser!(u64)))
        .arg(Arg::new("method")
            .short('m')
            .long("method")
            .num_args(1)
            .help("HTTP method to use (default: GET)")
            .value_parser(clap::value_parser!(String)))
        .arg(Arg::new("proxy")
            .short('p')
            .long("proxy")
            .num_args(1)
            .help("Proxy URL to use for the requests")
            .value_parser(clap::value_parser!(String)))
        .arg(Arg::new("silent")
            .short('s')
            .long("silent")
            .num_args(0)
            .help("Silent mode, suppresses the banner"))
        .arg(Arg::new("no_color")
            .short('n')
            .long("no-color")
            .num_args(0)
            .help("Disable color in output"))
        .arg(Arg::new("output")
            .short('o')
            .long("output")
            .num_args(1)
            .help("Output file to save the results")
            .value_parser(clap::value_parser!(String)))
        .arg(Arg::new("thirdparty")
            .long("thirdparty")
            .num_args(1)
            .default_value("http://example-thirdparty.com")
            .help("Third party domain to test")
            .value_parser(clap::value_parser!(String)))
        .arg(Arg::new("invalid_origin")
            .long("invalid-origin")
            .num_args(1)
            .default_value("http://example-invalid-origin.com")
            .help("Invalid origin to test")
            .value_parser(clap::value_parser!(String)))
        .get_matches();

    let url = matches.get_one::<String>("url").unwrap();
    let custom_headers = matches.get_one::<String>("custom_headers").map(String::as_str);
    let cookie = matches.get_one::<String>("cookie").map(String::as_str);
    let rate_limit = matches.get_one::<u64>("rate_limit").copied();
    let method_default = String::from("GET");
    let method = matches.get_one::<String>("method").unwrap_or(&method_default);
    let proxy = matches.get_one::<String>("proxy").map(String::as_str);
    let silent = matches.get_flag("silent");
    let no_color = matches.get_flag("no_color");
    let output = matches.get_one::<String>("output").map(String::as_str);
    let thirdparty = matches.get_one::<String>("thirdparty").unwrap();
    let invalid_origin = matches.get_one::<String>("invalid_origin").unwrap();

    scan(url, custom_headers, cookie, proxy, output, silent, no_color, rate_limit, method, thirdparty, invalid_origin).await;
}
