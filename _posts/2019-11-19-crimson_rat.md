---
layout: post
title:  Crimson RAT Classification
tags:   malware analysis
---

Analyzing a suspicious office document by googling.

{{more}}

## Analysis

Over the last weekend I received multiple emails containing an interesting office document. As it already looked like malware I simply threw the sample into my sandbox to get fast results. Unfortunately the first time the sample did not fully run as it needed user interaction.
Confirming the opening alert dialog box during the analysis brought the execution to a further stage and dropped an executable to disk.

Beeing already pretty happy about it I could now start to analyze the given executable and classify the sample to a known malware family. Nonetheless I wanted to see if I could extract certain executable manually from the office document since there were no network connections during the dynamic analysis.
<br>
As a first step I used the tool [_olevba_](https://www.decalage.info/python/olevba) to show all the containing code. By glancing through the whole code I noticed a large section of data which was decoded. Reading the decoder code it was pretty clear that this is the contained executable.

![VBA Code Snippet](/assets/images/crimson_rat/source_code.png)

To now extract the executable I decided to write a small python script. As input the script just takes the `olevba` output, uses regular expressions to select the encoded data and decodes it to an executable file which is written do disk.
<br>

```c
#!/usr/bin/python

import sys
import getopt
import re

def main(argv):
    inputfile = None
    outputfile = None
    try:
        opts, args = getopt.getopt(argv,"hi:o:",["ifile=","ofile="])
    except getopt.GetoptError:
        print('pe_extract.py -i <inputfile> -o <outputfile>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('pe_extract.py -i <inputfile> -o <outputfile>')
            sys.exit()
        elif opt in ("-i", "--ifile"):
            inputfile = arg
        elif opt in ("-o", "--ofile"):
            outputfile = arg

    if inputfile is None or outputfile is None:
        print('pe_extract.py -i <inputfile> -o <outputfile>')
        sys.exit(2)

    vba_file = open(inputfile, "r")
    vba_code = vba_file.read().strip().rstrip()

    re_search = re.search("[0-9]+(![0-9]+)+", vba_code, re.IGNORECASE)
    if re_search:
        encoded_content = re_search.group(0)
        splitted = encoded_content.split("!")
        output = open(outputfile, "wb")
        for x in splitted:
            output.write(bytes((int(x),)))
        output.close()
        vba_file.close()

if __name__ == "__main__":
    main(sys.argv[1:])
```
<br>

After finishing the script I realized that I could have done the whole decoding using [_CyberChef_](https://gchq.github.io/CyberChef/). To confirm that CyberChef would have been the shorter way I created a recipe which does the same as my python script.
<br>

```c
Regular_expression('User defined','[0-9]+(![0-9]+)+',true,true,false,false,false,false,'List matches')
Split('!',' ')
From_Decimal('Space',false)
SHA2('256')
```

<br>
Now after I also extracted the executable manually from the office document I was ready to find out what kind of malware it is. To do so the simplest way is mostly using one of the many search engines. To increase the chances of finding a clue I searched by the hash of the office document and the executable. I used the following tools to look for evidence to classify the malware.
<br>

- [_Virus Total_](https://www.virustotal.com/)
- [_Any Run_](https://app.any.run/)
- [_Hybrid Analysis_](https://www.hybrid-analysis.com/)
- [_Twitter_](https://twitter.com/)
- [_URLHaus_](https://urlhaus.abuse.ch/)

<br>

Unfortunately at the time of analysis I did not find any usefull clues. Therefore I had to look for other possibilities.

Running the executable again in the sandbox showed a little more about the behavior and also there were network connections established. Looking at the network related API calls pointed out evidence that it could be a Remote Access Tool. The process received various commands which were executed and performed data exfiltration.

![VBA Code Snippet](/assets/images/crimson_rat/network_code.png)

Using Google to search for these commands led to a site which wrote about [the tensions between India and Pakistan and related spear campaigns](http://www.malcrawler.com/did-pakistanstrikesback-both-by-jets-and-cyber/). Looking at the mentioned hashtag in the article gave me the idea to search for it on Twitter in connection with malware. The result was quite promising as I found a Twitter post by `@MalCrawler` which also wrote the article I found before. Looking at the comment section I finally found a potential malware name - Crimson RAT.

Reading a [Proofpoint Article about Crimson RAT](https://www.proofpoint.com/sites/default/files/proofpoint-operation-transparent-tribe-threat-insight-en.pdf) veryfied that this is indeed the Crimson RAT malware.

## Conclusion

Even without digging deeper and using a disassembler or similar it is possible to classify a malware sample. Somethimes the Malware family is already mentioned in the Virus Total comments or a classified sandbox report exsits, but somethimes the journey is a little longer. In my opinion it is nonetheless helpfull to look for further clues using "open-source intelligence" instead of digging directly into a disassembler.

<br>

Happy to hear about how other people tackle this challenge.


## IOC

```c
  Transfer details.xls [sha256: 82133319c6689de47034850e75fee274ca934dc6def5651fb5793b56a626aa56]
  Intel.exe [sha256: 886c394c284f3f334c0e385fe36ec1022037585810b9e39629fcbdc2ac4d27e1]
  INV11554.xls [sha256: 484ee5d1c239505d9012a81bdd6bfa0c8125f314baf43ca7f11772a2b8fcafba]
  Intel.exe [sha256: f874ab543bd1876707bb16cb7cc5f807eb039ebce29f6c898545ab12edaec9ff]
  File Path: %USERPROFILE%\Intel Graphics Driver\Intel.exe
  C2: 5.196.210.44 : 33401
```
