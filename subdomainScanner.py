import requests
import sys

# التأكد من وجود الدومين كوسيط
if len(sys.argv) < 2:
    print("Usage: python script.py <domain>")
    sys.exit(1)    

domain = sys.argv[1]

# فتح ملف subdomains.txt بطريقة آمنة باستخدام with
with open("subdomains.txt", "r") as file:
    subdoms = file.read().splitlines()

for sub in subdoms:
    sub_domains = f"http://{sub}.{domain}"
    
    try:
        response = requests.get(sub_domains)
        # لو الصفحة مش موجودة (404) ننتقل للعنصر التالي
        if response.status_code == 404:
            continue
    except requests.ConnectionError:
        continue  # لو حصل خطأ في الاتصال، ننتقل للعنصر التالي
    except Exception as e:
        print(f"Error accessing {sub_domains}: {e}")
        continue
    else:
        print("Valid domain:", sub_domains)  
