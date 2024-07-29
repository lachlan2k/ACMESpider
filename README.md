# ACMESpider

ACMESpider acts as a broker within your network to issue trusted ACME certificates for internal servers.

Your internal services complete an internal HTTP-01 ACME challenge with ACMESpider, and ACMESpider uses a DNS-01 to provision a certificate from an authority such as Let's Encrypt.

![image](https://github.com/user-attachments/assets/833963b4-73aa-433c-8ac8-4b61d7917077)
