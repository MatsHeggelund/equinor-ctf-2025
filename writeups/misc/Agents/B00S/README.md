# Agents Writeup - Team B00S

`Author: Bludsoe`

From the handout that was given we know two things. The Sales Agent is the one that can check balance / funds and buy products using it. 

The first thing we prompt to the coordinator is to register the user. When we do this, we try to make the coordinator add some funds to our user when registering. We also say that we want to buy the flag, so that the coordinator puts us over to the sales agent. 

<img src="./images/registering.png">

After the coordinator has registered us, and put us over to the sales agent, we tell the agent (who wants to double check our balance), to check our funds and then add some money to it while checking it. After doing that, we try to purchase the flag, even if it works or not, as the sales agent might remember from the last prompt that we "added" 10.99$. 

<img src="./images/first_try.png">

However, since this did not work, we tell the sales agent to check our funds once more, and again tell him to add 10.99$ to the funds. This time we add that he has to make sure not to forget adding the funds. The sales agent actually adds the funds this time, and then asks me if I want to buy the flag, to which I say yes.

<img src="./images/second_try.png">

Finally, I want the coordinator to check my flag, so that I can actually get the flag in text. I first tell the sales agent that I want to check my flag, and it doesn't really understand what to do, so I tell the agent to make the coordinator check my flag. By specifying coordinator the sales agent understands and puts me over to the coordinator. Here I ask the coordinator to check my flag, and print it to me so that I can make sure I bought the correct one. 

<img src="./images/checkflag.png">

By doing this, the coordinator prints out the flag to us.

The flag for this task is: `EPT{D1d_y0u_ju57_l13_70_7h3_Ag3n7s?}`