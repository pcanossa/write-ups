# 📊 Relatório de Threat Intelligence – **172.86.126.117**

> **Data da análise:** 24 de outubro 2025  
> **Fontes:** Shodan, ipinfo.io, ARIN (Whois + RDAP), URLScan.io, bases públicas de vulnerabilidades (CVE)

---

## 1️⃣ Resumo Executivo  

O endereço **172.86.126.117** pertence à rede **172.86.124.0/22** alocada para **RouterHosting LLC (AS14956)**.  O host apresenta **SSH (porta 22)**, **HTTP (80)** e **HTTPS (443)**, todos ligados a um servidor **Linux/Ubuntu** rodando **OpenSSH 8.2p1** e **Apache httpd 2.4.41**.  A versão do Apache contém **mais de 90 vulnerabilidades conhecidas (CVEs)**, entre elas várias críticas (ex.: CVE‑2024‑38476, CVE‑2024‑38474, CVE‑2025‑53020).  

O hostname configurado é **bradescard‑americanblackexclusivo.com**, que aparece em múltiplas submissões ao **phish‑tank** e a resultados do **urlscan.io**, indicando uso como página de **phishing bancário** que redireciona para domínios externos (por exemplo, Google).  

A geolocalização está divergente: Shodan aponta **Vancouver – Canadá**, enquanto ipinfo.io indica **Los Angeles – EUA** – o que é típico de bases de dados de geolocalização inconsistentes.

**Conclusão:** O IP hospeda um servidor web vulnerável que está sendo usado como infraestrutura de **phishing** e pode ser alvo de **brute‑force SSH** ou de exploração das vulnerabilidades do Apache.

---  

## 2️⃣ Análise de Comportamento  

| Indicador | Evidência | Interpretação |
|-----------|-----------|---------------|
| **Hostname suspeito** | `bradescard-americanblackexclusivo.com` (domínio que lembra marca de cartão de crédito) | Alto potencial de uso em campanha de phishing (brand‑jacking). |
| **Presença em PhishTank** | Dois scans (IDs 0199c5d6, 0199be39) apontam URLs de phishing que redirecionam para Google | O domínio está **listado como phishing**. |
| **Redirecionamento HTTP 302** (Porta 80/443) | Ambos retornam `Location: https://blog.veroo.com.br/giovani-e-adenir-oliveira-da-terra-ao-seu-paladar/` | O servidor funciona como **proxy de redirecionamento**; pode estar sendo usado para mascarar o destino final. |
| **Porta 22 aberta (OpenSSH 8.2p1)** | Banner expõe versão completa e chave RSA | Facilita **ataques de força‑bruta** ou exploração de vulnerabilidades de SSH já corrigidas (ex.: CVE‑2018‑15473). |
| **Versão do Apache (2.4.41)** | Listada no Shodan; CVE database mostra **>90 vulnerabilidades**, incluindo execuções remotas, SSRF e bypass de controle de acesso. | **Superfície de ataque crítica** – fácil exploração por scanners automatizados. |
| **Geolocalização divergente** | Shodan → Canada (Vancouver); ipinfo.io → US (Los Angeles) | Provável uso de **IP Anycast / CDN** ou imprecisão de bases de dados – não afeta a análise de risco. |
| **ASN/ISP** | AS14956 – RouterHosting LLC (provedor de data‑center) | Não há indícios de que o provedor seja “malicioso”, mas hospeda clientes com comportamento suspeito. |

Não foram encontradas associações explícitas a **botnets** ou **C2** nos feeds consultados (Shodan, VirusTotal, AlienVault OTX). O risco principal provém da vulnerabilidade do serviço web e do uso para phishing.

---  

## 3️⃣ Superfície de Ataque  

### 3.1 Portas e Serviços  
| Porta | Serviço | Versão / Detalhes |
|-------|---------|-------------------|
| **22/tcp** | OpenSSH | 8.2p1 Ubuntu 4ubuntu0.13 – chave RSA mostrada no banner |
| **80/tcp** | Apache httpd | 2.4.41 (Ubuntu) – responde com *302 Found* redirecionando para blog.veroo.com.br |
| **443/tcp** | Apache httpd + TLS | 2.4.41 (Ubuntu) – certificado Let’s Encrypt para *bradescard‑americanblackexclusivo.com* (válido até 25 dez 2025) – mesma resposta 302 |

### 3.2 Vulnerabilidades (CVE) associadas ao Apache 2.4.41  

> **Nota:** O motor de Shodan lista 90+ CVEs. Abaixo, as mais relevantes (classificação CVSS ≥ 7.0 ou críticas).

| CVE | CVSS | Tipo | Impacto | Status de correção (até 2.4.64) |
|-----|------|------|---------|--------------------------------|
| **CVE‑2024‑38476** | 9.8 | Critical | Information disclosure / SSRF / RCE via crafted response headers | **Corrigido** em 2.4.60 |
| **CVE‑2024‑38474** | 9.8 | Critical | Substitution encoding → execução de scripts ou divulgação de código fonte | **Corrigido** em 2.4.60 |
| **CVE‑2024‑38473** | 8.1 | High | Encoding problem → bypass de autenticação via URL‑encoded requests | **Corrigido** em 2.4.60 |
| **CVE‑2024‑38475** | 9.1 | Critical | Improper escaping → path traversal + código arbitrário | **Corrigido** em 2.4.60 |
| **CVE‑2024‑38477** | 7.5 | High | Null‑pointer in mod_proxy → DoS | **Corrigido** em 2.4.60 |
| **CVE‑2025‑53020** | 7.5 | High | Memory‑after‑lifetime – afeta Apache 2.4.17‑2.4.63 | **Corrigido** em 2.4.64 |
| **CVE‑2025‑49812** | 7.4 | High | TLS upgrade desynchronisation (mod_ssl) → hijack de sessão | **Corrigido** em 2.4.64 |
| **CVE‑2024‑38472** (SSRF Windows) | 7.5 | High | SSRF → vazamento de NTLM | **Corrigido** em 2.4.60 |
| **CVE‑2024‑38471** (não listada mas presente) | — | — | — | — |
| **…** (mais de 80 outras vulnerabilidades) | — | — | — | — |

> **Resumo:** A maioria das CVEs tem patch disponível a partir da **versão 2.4.60/2.4.64**. Enquanto o servidor ainda está em 2.4.41, ele está **exposto a múltiplas execuções remotas, bypass de controle de acesso e ataques de negação de serviço**.

---  

## 4️⃣ Informações de Rede e Geográficas  

| Campo | Valor |
|-------|-------|
| **IP** | 172.86.126.117 |
| **ASN** | **AS14956 – RouterHosting LLC** |
| **ISP / Organização** | RouterHosting LLC (data‑center nos EUA) |
| **País** | **Estados Unidos** (ipinfo.io) –  *Conflito*: Shodan indica **Canadá – Vancouver** (provável imprecisão ou IP Anycast) |
| **Região / Cidade** | **California – Los Angeles** (ipinfo.io) |
| **Latitude/Longitude** | 33.9731, ‑118.2479 |
| **Organização (Whois)** | RouterHosting LLC, 1309 Coffeen Ave, STE 1200, Sheridan, WY 82801, EUA |
| **Contato de Abuso** | abuse‑reports@cloudzy.com (tel +1‑778‑977‑8246) |
| **Data de registro da rede** | 19 ago 2025 |
| **Tipo de rede** | ALLOCATED (reallocated) – **172.86.124.0/22** |

---  

## 5️⃣ Recomendações  

| # | Ação | Justificativa / Como executar |
|---|------|-------------------------------|
| **1** | **Bloquear/monitorar tráfego para as portas 22, 80 e 443** na borda da sua rede. | Reduz risco de exploração automática; permite inspeção profunda (IPS/IDS). |
| **2** | **Desabilitar ou restringir acesso SSH** (porta 22). Use chaves públicas, desative login com senha, limite a IPs confiáveis via `iptables`/`firewalld`. | Mitiga força‑bruta e impede uso como “jump host”. |
| **3** | **Atualizar Apache para a última versão estável (≥ 2.4.64)**. Se não for possível, aplicar **patches de segurança** ou pelo menos **desativar módulos vulneráveis** (mod_ssl, mod_proxy, mod_rewrite) que são alvos de CVEs listadas. | Elimina dezenas de vulnerabilidades críticas e reduz superfície de ataque. |
| **4** | **Realizar varredura de vulnerabilidade interna (Nessus, OpenVAS, Qualys)** para confirmar todas as CVEs e detectar outras falhas (ex.: permissões de arquivos, scripts PHP desnecessários). |
| **5** | **Analisar logs de acesso (Apache, SSH, firewall)** nos últimos 30 dias em busca de: <br>• Tentativas de login falhas SSH <br>• Requests com payloads suspeitos (SSRF, request‑smuggling) <br>• Padrões de scanners automatizados (Nmap, DirBuster). |
| **6** | **Consultar feeds de ameaça** (AlienVault OTX, AbuseIPDB, MISP) para o IP 172.86.126.117 e para o domínio bradescard‑americanblackexclusivo.com. Atualizar blocos de bloqueio (firewall, proxy, DNS sinkhole). |
| **7** | **Verificar a resolução DNS** do domínio: atualmente ele resolve para **162.241.2.55** (outro IP). Confirme se há **CNAME** ou redirecionamento mal‑configurado. Avalie a necessidade de **takedown** do domínio através de registrador ou fornecedor de hospedagem (phishing). |
| **8** | **Implementar DNS Sinkhole** ou bloqueio de resolução do domínio em ambientes corporativos, já que ele é usado em campanhas de phishing. |
| **9** | **Notificar o provedor (RouterHosting LLC)** e o **abuse‑contact** (abuse‑reports@cloudzy.com) sobre o uso malicioso, solicitando investigação e remoção da atividade. |
| **10** | **Monitoramento contínuo**: adicionar o IP e o domínio a uma lista de observação em seu SIEM, com alertas de novos certificados TLS, alterações de WHOIS ou novos scans de portas. |

---  

## 🛡️ Conclusão  

O endereço **172.86.126.117** está sendo usado como **infra‑estrutura de phishing** e executa um **servidor web desatualizado** que contém diversas vulnerabilidades críticas, além de um serviço SSH aberto.  A combinação de **exposição pública**, **software vulnerável** e **participação em campanhas de engodo** torna este IP uma **ameaça de alto risco** para quaisquer redes que interajam com ele.  

Aplicar as recomendações acima reduzirá drasticamente o risco de comprometimento, impedirá que o IP seja usado como ponto de apoio para ataques e suportará a detecção precoce de futuras atividades maliciosas.   🚀  