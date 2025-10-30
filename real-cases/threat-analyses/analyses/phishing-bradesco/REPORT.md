# Threat Intelligence Report — Campanha Phishing Bradesco / American Express

**Analista:** Patrícia Canossa Gagliardi  
**Data:** 27/10/2025  
**Tipo de Ameaça:** Phishing Bancário / Exfiltração de Credenciais  
**Status:** Confirmada (Infraestrutura Ativa)  
**Plataformas afetadas:** Windows, Android, iOS  
**Fonte de Disseminação:** E-mail com link malicioso  
**Infraestrutura:** Google Cloud Run / RouterHosting / Linode (Akamai Connected Cloud)

---

## Resumo Executivo
Campanha de phishing direcionada a clientes Bradesco e American Express.
O e-mail malicioso contém link hospedado na Google Cloud Run que redireciona a uma página falsa (imitando o portal Bradesco), onde são coletadas credenciais bancárias (agência, conta, dígito e senha de 4 dígitos).
A infraestrutura alterna entre múltiplos IPs e provedores (Google Cloud, RouterHosting, Linode/Akamai), dificultando a detecção e a atribuição direta.

## Técnicas, Táticas e Procedimentos (TTPs)

| **MITRE ATT&CK ID** | **Tática** | **Técnica** | **Descrição** |
|-------|-------------|------------------|-----------------|
| T1566.002 | Initial Access | Phishing: Link Malicioso | Envio de e-mails com links falsos de convites Bradesco/American Express |
| T1056.001 | Credential Access | Input Capture (Web Form) | Captura de credenciais bancárias via formulário web falso |
| T1071.001 | Command & Control | Application Layer Protocol (HTTP/S) | Comunicação com `api.php` via POST JSON |
| T1036 | Defense Evasion | Masquerading | Uso de design, scripts e domínios semelhantes ao Bradesco |
| T1568.002 | Command & Control | Dynamic Resolution | Rotação de IPs e DNS para evasão de bloqueios |

## Indicadores de Comprometimento (IOCs)

### Domínios e IPs

| Tipo | Valor | Descrição | Risco | Observações |
|------|--------|------------|--------|--------------|
| Domínio | `redexclusiv-975736767249.southamerica-east1.run.app` | Link inicial hospedado na Google Cloud Run | Médio | Cloaking por sistema operacional |
| IP | `34.143.78.2` | IP resolvido do domínio acima | Baixo | Google Cloud |
| Domínio | `bradescard-americanblackexclusivo.com` | Página principal de phishing | **Crítico** | Em PhishTank (IDs 0199c5d6, 0199be39) |
| IP | `172.86.126.117` | Infraestrutura RouterHosting | **Crítico** | Apache 2.4.41 vulnerável, SSH exposto |
| IP | `172.237.50.16` | Infraestrutura Linode/Akamai | Médio | Nova resolução do domínio |
| IP | `162.241.2.55` | Resolução posterior | Médio | Alteração DNS |
| IP | `88.221.161.37` | Referenciado em HTML | Baixo | Akamai CDN (sem evidência maliciosa) |
| Domínio | `thunderhead.com` | CDN usada para exfiltração disfarçada | Médio | Cloudflare; uso como proxy |
| IP | `141.193.213.20` | Cloudflare (thunderhead.com) | Baixo | CDN legítima |
| IP | `141.193.213.21` | Cloudflare (thunderhead.com) | Baixo | CDN legítima |

### Scripts e Arquivos Maliciosos

| Tipo | Caminho / Arquivo | Função Observada | Risco | Observações |
|------|--------------------|------------------|--------|--------------|
| JavaScript | `/js/navegg.js` | Coleta de dados via Navegg | Médio | Uso de tracking legítimo reaproveitado |
| JavaScript | `/js/lembrarAgCta.js` | Armazena cookies com dados bancários (Base64) | **Crítico** | Roubo de agência/conta/dígito |
| JavaScript | `/js/fbevents.js` | Meta Pixel oficial | Baixo | Tracking ou retargeting |
| JavaScript | `/js/validaFormNaoCorrentista.js` | Envio de CPF para endpoint remoto | **Crítico** | Roubo de dados pessoais |
| JavaScript | `/js/detect-mobile.js` | Detecta SO móvel e altera links | Alto | Redireciona para apps falsos |
| JavaScript | `/js/one-tag.js` | Intercepta cliques e envia credenciais | **Crítico** | Envia para `thunderhead.com` (`siteKey=ONE-WDA4KRKODB-1484`) |
| JavaScript | `/js/index.js` | Manipula login bancário (agência/conta/dígito) | **Crítico** | Coleta e envia dados sensíveis |
| JavaScript | `/js/identificacao.js` | Captura senha virtual e comunica com API | **Crítico** | Exfiltra senha de 4 dígitos |
| PHP | `/api.php` | Endpoint de exfiltração (C2) | **Crítico** | Recebe dados via POST |
| PHP | `/identificacao.php` | Página falsa de login (teclado virtual) | **Crítico** | Simula página Bradesco legítima |

### URLs Relacionadas

| Tipo | Valor | Descrição | Risco | Observações |
|------|--------|------------|--------|--------------|
| URL | `https://blog.veroo.com.br/giovani-e-adenir-oliveira-da-terra-ao-seu-paladar/` | Página legítima usada como *decoy* | Baixo | Redirecionamento final via 302 |

---

## Avaliação de Risco

- **Nível de Ameaça Global:** **Crítico**  
- **Alvo:** Clientes do Banco Bradesco / American Express  
- **Motivação:** Roubo de credenciais financeiras  
- **Sofisticação:** Alta (cloaking, redirecionamento dinâmico, uso de CDNs legítimas)  
- **Evasão:** Alta (infraestrutura rotativa e mascarada por Google Cloud/Akamai)  


## Recomendações

1. Bloquear todos os domínios e IPs listados no perímetro (firewall, proxy, IDS/IPS).  
2. Acionar **takedown** do domínio `bradescard-americanblackexclusivo.com` junto ao registrador.  
3. Implementar monitoramento contínuo de domínios similares (`bradescard-*`, `americanblack*`).  
4. Inserir hashes dos arquivos JS em bases internas de IOC.  
5. Orientar clientes e colaboradores sobre phishing bancário com URLs legítimas aparentes.  
6. Relatar os indicadores às autoridades e CERT-BR.

## Referências MITRE ATT&CK
* T1566.002 - Phishing: Link Malicioso
* T1056.001 - Input Capture (Web Form)
* T1071.001 - Application Layer Protocol (HTTP/S)
* T1036 - Masquerading
* T1568.002 - Dynamic Resolution


## Metadados

- **Fonte original:** E-mail fraudulento com botão “Aceitar Convite”  
- **Data da captura:** 24–27 de outubro de 2025  
- **Sistema analisado:** Windows 10 VM / Kali Linux VM  
- **Ferramentas utilizadas:** Shodan, IPInfo, RDAP, URLScan, PhishTank, DevTools, `ip-analysis.py`, ``domain-analysis.py``  
- **Nível de confiança:** **Alta**  
- **Assinatura digital:** gpt-oss/120b (via Ollama Cloud)

