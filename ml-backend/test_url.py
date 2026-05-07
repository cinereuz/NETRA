import requests

url_test = "https://googgle.com/"

response = requests.post(
    "http://localhost:5000/predict",
    json={"url": url_test}
)

hasil = response.json()

print(f"\nURL      : {url_test}")
print(f"Kategori : {hasil['kategori'].upper()}")
print(f"Confidence: {hasil['confidence']}%")
print(f"Berbahaya : {hasil['berbahaya']}")
print(f"Method   : {hasil['method']}")
print(f"Detail   : {hasil['detail']}")