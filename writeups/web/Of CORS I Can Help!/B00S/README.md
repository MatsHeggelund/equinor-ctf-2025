# Of CORS I Can Help! Writeup - Team B00S

`Author: Bludsoe`

The first thing I did was check the source code for the task. Here I was able to find two crucial parts of the code. The first crucial part, is the actual function responsible for either giving the value of the flag if the user has permission (which Jenny has) or give an error if the access is forbidden.

<img src="./images/get_flag.png" width=75%>

This means that I couldn't simply just go to the `/flag` part of the website to get the flag, as I do not have access to the flag. Because by doing this, Jenny would just say that she cannot disclose that information

<img src="./images/failure.png" width=75%>

However, this is where the other crucial part of the source code comes into play. Jenny gives back some information depending on what URL you give out. However asking for the `/flag` directly does not work because of a url check, that checks if the url ends with exactly `/flag`.

<img src="./images/urlcheck.png" width=75%>

However, the vulnerable part here is that it simply checks if the path starts with `/flag` as the string. There is no other checks, which means that we can bypass this quite simple. To bypass this check, we simply URL-encode the word `flag` using BurpSuite decoder window

<img src="./images/urlencoding.png" width=75%>

By asking Jenny for the URL using this encoded version, the URL check would no longer say that the path starts with `/flag`, and Jenny would then give out the content of the flag page, essentially giving us the flag

<img src="./images/success.png" width=75%>

The flag we got from this task was: `EPT{CORS_t0tally_trU5t5_y0u}`