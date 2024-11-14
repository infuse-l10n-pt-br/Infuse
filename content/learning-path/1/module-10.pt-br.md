---
style: module
title: Exercício de Capture-a-Bandeira (CtF)
description: Nós criamos um exercício do tipo Capture-a-Bandeira — *Capture-the-Flag* (CtF) em inglês — através do qual estudantes podem analisar um email de phishing e a sua infraestrutura relacionada. O exercício pode ser usado como um exercício adicional para prática ou checagem de habilidades, e ele pode ser lido aqui.
weight: 10
---

Nós criamos um exercício do tipo Capture-a-Bandeira — *Capture-the-Flag* (CtF) em inglês — através do qual estudantes podem analisar um email de phishing e a sua infraestrutura relacionada. O exercício pode ser usado como um exercício adicional para prática ou checagem de habilidades, e ele pode ser lido abaixo.

Você está trabalhando no movimentado escritório de redação Press, onde você atua como administrador de TI. Você está em sua mesa, completamente concentrado em suas tarefas e rodeado por monitores. A sua colega, Alia da Contabilidade, corre para você assim que te vê com uma expressão preocupada em seu rosto. Ela te diz que ela te encaminhou um email que alega ser do PayPal, exigindo ação imediata por conta de uma atividade suspeita na conta. A organização Press depende do PayPal para processar pagamentos associados a assinaturas. O seu interesse é fisgado assim que você reconhece o potencial para um ataque malicioso, e você começa uma investigação.

*Essa atividade exige a análise dos arquivos de um email e uma página inicial fictícios para o seu seguimento. Baixe os arquivos aqui: {{< fontawesome "solid/download" >}} [Materais do CtF](/files/ctf-materials.zip)*

### Questão 1: Qual é o endereço do remetente do e-mail?

{{< question title="Instruções" open="true" >}}
Descubra como o endereço do remetente do e-mail seria exibido em um cliente de e-mail se o e-mail fosse aberto.
{{< /question >}}

{{< question title="Dicas" >}}
Há várias formas de visualizar o e-mail da forma como ele seria exibido para o destinatário. A maneira mais direta seria abrir o arquivo em um cliente de e-mail, que é o que fizemos nos exemplos abaixo. No entanto, no contexto de uma ameaça direcionada, isso pode ser uma péssima ideia: o arquivo pode conter scripts que podem explorar vulnerabilidades em clientes de e-mail, coletar informações sobre o dispositivo, ou carregar recursos externos (como arquivos de mídia ou pixels de rastreamento), que podem revelar o seu endereço IP ao agressor. No caso deste exercício, é seguro abrir o arquivo EML em seu cliente de e-mail de escolha. Para casos reais, porém, considere as seguintes alternativas:

* Usar um cliente de e-mail em uma máquina virtual que pode ser revertida para uma cópia anterior segura
* Abrir o arquivo em um editor de texto e leia diretamente o conteúdo HTML
* Renomear o arquivo para `.mht` e abra-o em um navegador (considere usar uma máquina segura e isolada e se conectar a uma VPN para evitar a captura de seu endereço IP através de pixels de rastreamento)
* Usar um serviço online como <https://www.emlreader.com/> ou <https://www.encryptomatic.com/viewer/> para visualizar o e-mail. A ferramenta de análise de cabeçalho do MXToolBox <https://mxtoolbox.com/EmailHeaders.aspx> (utilizada mais à frente neste exercício) também renderiza o conteúdo HTML do e-mail se você incluí-lo com os cabeçalhos fornecidos.
* Usar uma ferramenta do eDiscovery que pode renderizar arquivos EML
* Hospedar o seu próprio serviço de renderização de arquivos EML, como <https://github.com/xme/emlrender>

Neste exercício, iremos abrir o e-mail (`paypal.eml`) em um cliente de e-mail.

![Captura de tela mostrando o arquivo paypal.eml no navegador de arquivos. Abriu-se o menu de opções, clicando em Open With. Dentre as opções disponíveis, escolhemos o programa Outlook (aqui destacado com um retângulo vermelho).](/media/uploads/CTF1_open_in_mail_program.png)

Observando o e-mail renderizado, podemos encontrar o aparente endereço de e-mail do remetente.

![Image of an ostensible email from Paypal indicating suspicious account activity with a link to verify the account. The email is from paypal@service.com](/media/uploads/CFT2_sender_address.png)
{{< /question >}}

{{< question title="Answer" >}}
O endereço exibido como endereço de e-mail do remetente é [paypal@service.com](mailto:paypal@service.com)
{{< /question >}}

### Question 2: What is the subject of this email?

{{< question title="Instructions" open="true" >}}
As we continue to review the email, we look for more characteristics which could be indicative of spam or malicious messages. Let’s look at the subject and some other signs within the text! If you are reading the email in a text editor, you will find it in the Subject: line.
{{< /question >}}

{{< question title="Hints" >}}
![A screenshot of the email in question, highlighting the subject line thereof](/media/uploads/CTF3_email_subject.png)

Here are some key trigger points to watch out for in a phishing email:

* Sense of urgency
* Weird opening, does not address you by name
* Grammar errors
* The sender address or URLs within the email are obfuscated or do not match the website the email claims to be from
{{< /question >}}

{{< question title="Answer" >}}
The email subject line is: _We called you and you didn't answer_
{{< /question >}}

### Question 3: What is the action requested?

{{< question title="Instructions" open="true" >}}
When we look at a potentially malicious email, we also need to figure out what the sender wanted us to do. What action do you assume that the sender wanted the recipient to do?
{{< /question >}}

{{< question title="Hints" >}}
![A screenshot of the email with "detected suspicious activity", "payments have been suspended", "complete account verification" and the call to action link saying "resume payments" all underlined](/media/uploads/CTF4_email_actions.png)
{{< /question >}}

{{< question title="Answer" >}}
Click on one of the two links within the email.
{{< /question >}}

## Recognizing the Threat

### Question 4: Defang the “Confirm” Link

{{< question title="Instructions" open="true" >}}
As we go deeper in the analysis, the first step to do is to understand the difference between suspicious links. When we analyze potentially suspicious links, we typically defang them–this means replacing some characters so that the link cannot be accidentally clicked or does not trigger any automated link- or virus-scanning mechanisms. Defanging links is considered best practice in security investigations. Defanged links will not automatically turn into clickable links but still retain the original link information, for instance hxxp[://]www[.]google[.]com.
{{< /question >}}

{{< question title="Hints" >}}
You can defang a link in a text editor. Here we will use [CyberChef](gchq.github.io/CyberChef) to defang the URL as we will use CyberChef for other steps as well. CyberChef is a web application with a huge number of functions which can help you with analyzing security-related data. Here’s a [very brief introduction](https://udel.codes/cyberchef.html) to its layout and functions.

As part of this exercise, play around with CyberChef and defang the “please confirm” link from the attached email.

![A screenshot of how to right click on an email and then press "copy link"](/media/uploads/CTF5_copylink.png)
First, we copy the hyperlink from the email.

![A screenshot of CyberChef, with "defang" being typed into its search bar](/media/uploads/CTF6_defang.png)
Then, we take the “Defang URL” input from CyberChef and drag it into the “Recipe” section

![A screenshot of CyberChef successfully defanging an email](/media/uploads/CTF7_defanged.png)

Once we’ve pasted the URL into the input section in CyberChef, it will automatically output a defanged version thereof.
{{< /question >}}

{{< question title="Answer" >}}
hxxps[://]d[.]pr/mUxkOm
{{< /question >}}

### Question 5: Use CyberChef to extract and defang all the links in the email

{{< question title="Instructions" open="true" >}}
You can use CyberChef to perform a lot of different analysis tasks. This time, find and describe a workflow to easily extract and defang all of the links from the email.
{{< /question >}}

{{< question title="Answer" >}}
You can use a ‘recipe’ – or a series of connected steps –in CyberChef to carry out a more complex analysis. To obtain and defang all the URLs in the message, all you need to do is run a recipe with the “extract URLs” and “defang URLs” workflows and paste the full content of the email (copied from a plain text editor) as input. If you were to tick the “unique” checkbox under “extract URLs”, you will see that the results will differ from those from the screenshot, and it will only output a single URL, the same one you defanged above. The fact that there is just one URL, repeated many times, within the email is great news for us–it will make our analysis much more straightforward. \

![A screenshot of a CyberChef recipe which first extracts all the URLs from a text file and then defangs them](/media/uploads/CTF9_cyberchef.png)
{{< /question >}}

## Passive Investigation of URLs, Hostnames, and IP Addresses

### Question 6: When was the URL defanged in question 4 submitted to VirusTotal?

{{< question title="Hints" >}}
For the next few questions, we will use [VirusTotal](https://www.virustotal.com/)**.** It’s an online service that acts like a security scanner for suspicious files and URLs. Think of it as a digital inspector. You can upload a file or provide a URL, and VirusTotal scans it with antivirus engines and website checkers from dozens of different security companies. It also performs some additional analysis. This gives you a quick overview of whether the file or website is likely to be malicious. It's a valuable tool to help you identify potential threats before you open an attachment or click on a link. It also contains metadata about files which may be helpful. Here we will use the entry history to find out when a malicious indicator was first observed.

Paste the URL from question 4 into VirusTotal (this time, you need to paste the full URL, not the defanged version). Go to “details” tab and look at the URL capture history.

![A screenshot of VirusTotal history, showing three dates: first submission, last submission, last analysis](/media/uploads/CFT9_VirusTotal.png)
{{< /question >}}

{{< question title="Answer" >}}
08/20/2018
{{< /question >}}

### Question 7: What does VirusTotal give as the serving IP address for the URL defanged in question 4?

{{< question title="Hints" >}}
Also looking through the “details” tab in VirusTotal, look up the serving IP address.

![A screenshot of VirusTotal showing an HTTP response, with the final URL and serving IP address given](/media/uploads/CTF10_VirusTotalIP.png)
{{< /question >}}

{{< question title="Answer" >}}
52.89.102.146
{{< /question >}}

### Question 8: how many vendors on VirusTotal detect this URL as malicious?

{{< question title="Instructions" open="true" >}}
When viewing the URL in VirusTotal, look up all the details under the “detection” tab. For a deep dive into what VirusTotal means by detection and what its methodologies are, check out [its documentation](https://docs.virustotal.com/).
{{< /question >}}

{{< question title="Answer" >}}
5 Vendors
{{< /question >}}

### Question 9: In which registrar was the domain defanged in question 4 registered?

{{< question title="Instructions" open="true" >}}
In order to look up information related to a domain registration, we can use a whois lookup. You can conduct such a lookup either through a command line tool on your device or through a dedicated app.
{{< /question >}}

{{< question title="Hints" >}}
Here we use a whois website to extract it

![A screenshot of a WHOIS lookup of the d.pr domain](/media/uploads/CTF11_whois.png "image_tooltip")
{{< /question >}}

{{< question title="Answer" >}}
Internet Technology Solutions
{{< /question >}}

### Question 10: Where is the serving IP that you identified through VirusTotal geographically located?

{{< question title="Instructions" open="true" >}}
IP addresses are loosely tied to geographical locations, such as cities or districts. There are many online services where you can input an IP address and learn more about where it’s most likely located. While this type of check is not perfect and can sometimes make mistakes, it can nonetheless be an important part of malicious infrastructure investigations.

It’s worth comparing the information you receive from a whois lookup with that you receive from IP location searches. You might learn that the IP address you are trying to investigate belongs to a VPN provider or a big tech company such as Google–if this is the case, then you will not learn much from those investigations; the IP location will likely correspond to one of those companies’ server farms and might have little to do with the location of the person or entity you’re trying to investigate.

![A screenshot of a geoIP lookup of an IP address, showing that it originated in Portland, Oregon](/media/uploads/CTF12_geoIP.png "image_tooltip")
{{< /question >}}

{{< question title="Answer" >}}
Portland, Oregon, United States
{{< /question >}}

## Passive Investigation of Email Headers

### Question 11: what is the return path of the initial email you looked up?

{{< question title="Instructions" open="true" >}}
For the next few questions, we will be using a tool called [MxToolbox](https://mxtoolbox.com/). It’s a tool which can analyze email headers, hostnames, spam status, and much more. We will focus on its [header analyzer](https://mxtoolbox.com/EmailHeaders.aspx) feature, in which you can copy and paste all of the headers of an email (or even the whole email!) and run some basic analytics on them.
{{< /question >}}

{{< question title="Hints" >}}
First, open the email using a plain text editor of your choice and copy its content. Then, paste them into the MxToolbox’s “Analyze Headers” tool

![A screenshot of email headers being pasted into MX Toolbox Analyser](/media/uploads/CTF8_MX_analyzer.png)

Once you press “Analyze Header”, you can see the return path

![A screenshot of MX Toolbox giving a complex Return-Path based on the headers it analyzed](/media/uploads/CTF13_return_path.png)
{{< /question >}}

{{< question title="Answer" >}}
paparazi@rjttznyzjjzydnillquh.designclub.uk.com
{{< /question >}}

### Question 12: What are the first hop and SMTP server address of that email?

{{< question title="Instructions" open="true" >}}
Go to the file “mx-toolbox-header-analysis”, look into the relay information section.

![Another screenshot of the MX Toolbox analytics, with an initial relay highlighted](/media/uploads/CTF14_relay.png)
The address of the mail server

![Another screenshot of the MX Toolbox analytics, with the relay address highlighted](/media/uploads/CTF15_address.png)
{{< /question >}}

{{< question title="Answer" >}}
First hop: efianalytics.com 216.244.76.116

SMTP: `2002:a59:ce05:0:b0:2d3:3de5:67a9`
{{< /question >}}

## Active Investigation of Malicious Web Pages

### Question 13: What is the victim Id present in the code of the website?

{{< question title="Instructions" open="true" >}}
If the recipient of the email clicked on the link they would arrive at a landing page. Go to the file in the activity package to open “paypal.html”, look into the source code and search for the victimID. Use CyberChef to decode it to find a string of text.
{{< /question >}}

{{< question title="Hints" >}}
In this exercise, you will encounter a string of text encoded in Base64. Base64 is a technique for transforming text that has many purposes, but in this case aims to obfuscate a string of text: the string is still there, it’s just saved in a way that cannot be easily spotted by the human eye or by a simple text search. If this is the first time in your work you’ve encountered Base64, it’s worth reading [a little more about it and other obfuscation formats](https://anithaana3.medium.com/common-text-encoding-methods-for-code-obfuscation-9399757eb5c3). Malware authors like to obfuscate some text strings within their programs using a technique such as Base64 in order to make it more difficult to analyze.

CyberChef can encode and decode Base64 text.

We open once again the code attached of the phishing page (.html)

![A screenshot of an html file being right clicked in Windows Explorer, and then opened in Notepad](/media/uploads/CTF16_open_webpage_notepad.png)

we search for the victimID in the source code
![A screenshot of someone searching through the plain text file opened in Notepad and finding a data item called "victimID"](/media/uploads/CTF17_searchID.png)

Then we can paste the value we discovered into CyberChef. The tool has a magic wand feature which automatically detects and converts encoding–we could use that!

![A screenshot of CyberChef decoding Base64 input into plain text](/media/uploads/CTF18_cyberchef_result.png)

Yay! The magic wand detected that the input is encoded with Base64 and decoded it automatically, giving us the answer!

![A screenshot of CyberChef's magic wand feature](/media/uploads/CTF19_cyberchef_wand.png)
{{< /question >}}

{{< question title="Answer" >}}
Th1s_1s_pH1sh1ng_Em3il
{{< /question >}}

## Other resources and links

{{% resource title="Access Now helpline community documentation for responding to suspicious/phishing emails" languages="English" cost="Free" description="Client Receives a Suspicious/Phishing Email" url="https://accessnowhelpline.gitlab.io/community-documentation/58-Suspicious_Phishing_Email.html#" %}}

{{% resource title="List of all DNS record types" languages="English, Chinese, Japanese, Korean, Russian, Serbian, Ukrainian, Esperanto, Hungarian, Vietnamese, Italian, Spanish, French" cost="Free" description="Includes (almost?) all DNS record types." url="https://en.wikipedia.org/wiki/List_of_DNS_record_types" %}}

{{% resource title="Amnesty reports on phishing campaigns" languages="Multiple, depending on the report" cost="Free" description="A list of examples of how a targeted phishing campaign against human right defenders, activists and journalists looks" url="https://www.amnesty.org/en/search/phishing/" %}}
