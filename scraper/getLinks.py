from bs4 import BeautifulSoup
import requests
from urllib.parse import urljoin


def getDropdownNames(url="https://urnik.fov.um.si/"):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.content, 'html.parser')
        iframe = soup.find('iframe', {'id': 'iframeContent'})

        if not iframe or 'src' not in iframe.attrs:
            print("No iframe available!")
            return []

        iframeUrl = urljoin(url, iframe['src'])

        iframeResponse = requests.get(iframeUrl, timeout=10)
        iframeResponse.raise_for_status()

        iframeSoup = BeautifulSoup(iframeResponse.content, 'html.parser')

        dropdowns = iframeSoup.find_all('select')

        names = []

        for dropdown in dropdowns:
            options = dropdown.find_all('option')
            for option in options:
                text = option.text.strip()
                if text and text[0].isnumeric():
                    names.append(text)
        return names
    except requests.Timeout:
        print(f"Request timed out for {url}")
        return []
    except requests.RequestException as ex:
        print(f"Network error: {ex}")
        return []
    except Exception as ex:
        print(f"Unknown error: {ex}")
        return []
