# Breadcrumbs Writeup - Team B00S

`Author: Bludsoe`

The first thing we did was to figure out the functionality of the page. The page contained a simple "keyboard" with a set of characters,
and by clicking on them you would either get no form of response on the page, or get the letter you clicked as output.

<img src=".\images\functionality.gif" width="700" height="250" />

From the above GIF, you can see that clicking the characters forming the start of the EPT flag, yields the start of the flag as output on the webpage. This tells us that this "keyboard" works as some kind of oracle, that gives more and more output if you send the correct request (based on your last request), or removes the output if your request is incorrect. To find the full flag, you would simply have to request all the correct characters, in the correct order they appear in the flag.

To figure out how the oracle checks your current progress and figures out how your request is correct or incorrect, we used `BurpSuite` look at the request parameters we sent when clicking a button on the keyboard. The images below shows the request the browser sends when you click the letter E on the keyboard. We see a session cookie that looks a lot like a JVC token, containing some information, and then a signature of some kind. By decoding the first part of the token using `Base64`, we see that there is some information in it. The first part `fidx`, is how many correct letters have been requested before the current request. Since `E` is the first correct letter in the flag, this value is set to 0. The second part is simply the session_id.

<img src=".\images\e-request.png" width="500" height="350"/> <img src=".\images\e-request-jvcdcode.png" width="500" height="350">

If we look at the response, we can also get some useful information. We see that the response header has a set-cookie value, that updates the current session value. By decoding the first part of this value, we can see that the value of `fidx` has now been set to 1, because we have requested 1 correct letter according to the correct order of the flag. 

<img src=".\images\e-response.png" width="500" height="250" /> <img src=".\images\e-response-jvcdcode.png" width="500" height="250" />

To confirm this "system", we can also take a look at what happens if we then make a second request with the letter `P`. 

<img src=".\images\p-request.png" width="700" height="350" /> 

If we compare the session token from the last response to our request now, we can see that these two are exactly the same. 

e-response - `eyJmaWR4IjoxLCJzZXNzaW9uX2lkIjoiMmZhOTE0YzktMWVhMi00OGNjLWE2MDMtNTViZWUzMWFlMWExIn0` 

p-request - `eyJmaWR4IjoxLCJzZXNzaW9uX2lkIjoiMmZhOTE0YzktMWVhMi00OGNjLWE2MDMtNTViZWUzMWFlMWExIn0`

This means that to tell the oracle the progress you've made, you need to include the session token from the previous response. based on this information, we can create an automatic script, that brute-forces all characters with the same token for each request, until we get a valid response. After a valid response, we save the new session token, and then start brute-forcing the next character. Then, whenever we hit the `}` character, we know that's the end of the flag, and we can stop the loop. A well-performing script for this would be:
```Python
import requests
from bs4 import BeautifulSoup
from string import ascii_lowercase, ascii_uppercase, digits

CANDIDATES = list(digits + ascii_lowercase + ascii_uppercase +
                  "{}_-.,:;!@#$%^&*()[]\\/<>?+|`~\"'")

url = "https://breadcrumbs.ept.gg/"

session = requests.Session()
curr = ["E", "P", "T", "{"]

prev_cookie = ""
for el in curr:
    headers = {"Cookie": f"session={prev_cookie}"}
    response = session.get(url + el, headers=headers)
    prev_cookie = response.cookies.get("session")

while True:
    for candidate in CANDIDATES:
        headers = {"Cookie": f"session={prev_cookie}"}
        response = session.get(url + candidate, headers=headers)
        soup = BeautifulSoup(response.text, "html.parser")
        elements = soup.find_all(class_="text-center")

        if len(elements) == 3:
            curr.append(candidate)
            print("".join(curr))
            prev_cookie = response.cookies.get("session")
            break
    if "}" in curr:
        break
```

`Explaination of the run-flow of the above code:` We first create a list containing the possible characters in the flag based on the characters found on the keyboard on the website. Then we create a variable for the URL. Before starting the loop, we simply create a starting-point with the characters we already know the flag will start with to make the script finish faster. Then we start an infinite loop that will run until the whole flag is found. Here we go through each candidate and send a request with the current session token. If we request the correct letter, there will be 3 elements containing the "text-center" class, instead of 2. If this is the case, we update the session token to the one from the response, and then start going through the candidate-list again with the new token. This is essentially the process until we hit `}`, and then we stop the infinite loop.

By running this script it would essentially print out the flag: `EPT{2a65f323-6df3-a713-bc1a-e80afb6ca9fd}`