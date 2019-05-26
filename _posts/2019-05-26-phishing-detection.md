---
layout: post
title:  Phishing detection
tags:   phishing
---

Due to more and more phishing attempts againt the company I'm working for I looked for a way to detect them as soon as possible.

{{more}}

<br/>
Based on various discussion with other security analysts I decided on a way how to detect potential phishing sites. The algorithm which decides if a website is phishy or not is actually not too complicated. I didn't write it myself because already an amazing project covers this exact topic. [1]
In the `suspicious.yaml` file it is possible to define various keywors and assign them a score. This score is then calculated for each given domain using the keywords, the Shannon entropy and the Levenshtein distance. The domains which are used as input are taken from a project called certstream. [2]
Certstream is an aggregated feed of newly created certificates from a collection of Certificate Transparency Lists. <br/>
To get even more potential phishing domains I linked a list of newly registered domains. This list is published once a day and run through the domain scoring algorithm which decides if a domain is a potential phishing site or not. [3]
If configured to a certain company or industry not too many false positives should appear. To get notified whenever a new potential phishing domain is found I added a email notification service.<br/>
Now I always get notified when a new potential phishing site appears and can verify it using various different services and whenever needed request a take-down.
In the end I didn't really have to do a lot of programming because a many really great projects and tools already exist.
If you're interested in this project you can find it [_here_](https://github.com/stoerchl/phishing_catcher/){:target="_blank"}. 

<br/>
[1] https://github.com/x0rz/phishing_catcher
[2] https://github.com/CaliDog/certstream-python
[3] https://whoisds.com/newly-registered-domains

