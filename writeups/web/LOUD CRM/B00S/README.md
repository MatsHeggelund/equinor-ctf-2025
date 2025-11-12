# LOUD CRM Writeup - Team B00S

`Author: Bludsoe`

By looking at the source code we were given, I was able to find a weakness in the code that made it possible to bypass the registration checks, and overwrite Alice's password to something I knew

<img src="./images/vulnerability.png" width="100%">

The source code only checks if the username equals the username in all capital letters. The reason for this is that when registering, the handle you give is always typed in capital letters. There is no way to write your handle in lowercase.

<img src="./images/register.png" width="100%">

However, by checking the network tab in inspect element, I was able to edit and resend the POST packet being sent from the browser. By doing this, I was able to change my handle from all uppercase `ALICE` to a lowercase handle `alice`. Because of this, the check `username == username.upper()` did not give a True value, and the whole if-statement became false, making the code register a new password on the `Alice` account.

<img src="./images/resend-postreq.png" width="100%">

Then I was simply able to login using the Alice handle, and my new and very secure password: `password`.

<img src="./images/success.png" width="100%">

After logging in we were able to retrieve the flag. We also see that I have overwritten the display name of the account to be my name `Bludsoe`. 

The flag from this task was: `EPT{LOUD_HANDLE_OVERRIDE}`