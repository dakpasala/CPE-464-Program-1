# cpe 464 - packet trace program  
**author:** Dakshesh Pasala  

---

### overview  
This assignment was definitely tricky at first, but after spending a lot of time reading through the code and looking stuff up, I actually started to get what was going on. I kind of had to slow down and understand each layer (ethernet → ip → tcp/udp/icmp) instead of just trying to make it print the right thing. Once I did that, everything made way more sense.  

---

### process  
I built this one piece by piece — ethernet first, then ip, and then the other headers. It was a lot of trial and error and comparing against the diffs to make sure the formatting matched exactly.  

The no bitshifting / dividing / multiplying rule was actually kind of fun once I got used to it. I had to use masking and random little tricks like `ihl + ihl + ihl + ihl` instead of `ihl * 4` but this didn't even matter because it wasn't counted as bitshifting. Ended up learning way more about how these bits are packed in memory than i expected.  

---

### checksum stuff  
The checksum part took a while to wrap my head around. The tcp checksum uses something called a pseudo header — it’s not actually sent, it’s just used to calculate the checksum. I thought of it like an amazon box label: you care about what’s inside, but you still check the label to make sure it’s going to the right place, then you throw it out.  

---

### notes  
- no bit shifting, dividing, or multiplying anywhere  
- lots of masking and pointer math  
- formatted to match the diff exactly  
- spent a ton of time reading and re-reading the code until it clicked  
- added comments so future-me doesn’t forget why i did something  

---

### reflection  
Honestly I’m proud of this one. I went from just trying to get it to even run after running make to actually understanding every piece of the packet, which is shown by the immense amount of comments I added. Learned way more than I expected about how data really moves around underneath everything. Kind if cool to see it all broken down like this.  

---