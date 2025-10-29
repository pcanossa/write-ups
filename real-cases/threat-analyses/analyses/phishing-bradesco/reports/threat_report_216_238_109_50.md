# 📋 Relatório de Inteligência de Ameaças – **216.238.109.50**

---

## 1. Resumo Executivo
O endereço **216.238.109.50** pertence ao provedor de cloud **Vultr** (ASN AS20473) e está localizado em **Osasco, São Paulo – Brasil**. O host apresenta as portas **22 (SSH), 80 (HTTP), 443 (HTTPS), 500/UDP (IKE VPN) e 7011/TCP** abertas. O serviço SSH roda **OpenSSH 7.6p1**, versão vulnerável a diversas CVEs conhecidas. A porta 500 indica que o servidor está atuando como terminador de VPN (IPsec/IKE). Vários domínios associados ao IP (ex.: *regularizandocpf.com, rendaverificada.com, portalregularizacao.com* etc.) foram analisados pelo URLScan.io e apresentam páginas com conteúdo suspeito de **phishing/ scams de “regularização de CPF”**. As tags do Shodan apontam para **“cloud”** e **“vpn”**, reforçando o perfil de um servidor alugado e possivelmente utilizado como ponto de apoio para atividade maliciosa.

---

## 2. Análise de Comportamento

| Fonte | Indicador | Interpretação |
|-------|-----------|--------------|
| **Shodan** | Tags: *cloud, vpn*; serviços expostos (SSH, IKE) | Servidor público na nuvem que oferece acesso remoto (VPN/SSH). |
| **OpenSSH 7.6p1** (porta 22) | Versão antiga (lançada 2017) | Vulnerável a CVEs como **CVE‑2018‑15473**, **CVE‑2019‑6111**, **CVE‑2020‑15778** etc. |
| **Porta 500/UDP (IKE)** | Mensagem IKE “DOI Specific Use”, sem criptografia habilitada | Possível túnel VPN mal configurado; pode ser usado para “túnel” de tráfego malicioso ou como ponto de saída de botnet. |
| **Porta 7011/TCP** | Serviço não identificado (padrão de alguns trojans/controle remoto) | Recomendado estudo (banner ou *service fingerprint*). |
| **URLScan.io** | 10 domínios apontando para o mesmo IP; maioria marcada como *suspect*; conteúdos relacionados a “regularização de CPF” e blog genérico | Indica campanha de *phishing* ou *scam* hospedada no servidor. |
| **Whois/ARIN** | Organização: *Vultr Holdings, LLC*; ISP: *The Constant Company, LLC* | Não há indícios de que o IP seja “abuso” conhecido da Vultr; porém a natureza de “cloud rental” facilita a criação rápida de infra‑estrutura maliciosa. |
| **Última aparição** | Shodan – 2025‑10‑27 | O host está ativo recentemente. |

**Conclusão:** Há forte indício de que o IP está sendo usado como **infraestrutura de apoio para campanhas de phishing/ scams**, possivelmente suportadas por um túnel VPN e acesso SSH aberto. A presença de portas vulneráveis aumenta o risco de comprometimento adicional ou de servir como *pivot point* para invasores.

---

## 3. Superfície de Ataque

### 3.1 Portas e Serviços
| Porta | Protocolo | Serviço / Banner | Comentário |
|-------|-----------|-------------------|------------|
| **22** | TCP | OpenSSH 7.6p1 (banner “SSH‑2.0‑OpenSSH_7.6p1”) | Versão desatualizada; vulnerável a múltiplas CVEs. |
| **80** | TCP | HTTP – resposta **404 Not Found** | Não serve conteúdo próprio, mas pode redirecionar/servir páginas via proxy. |
| **443** | TCP | HTTPS – Apache/2.4.58 (Ubuntu) | Servidor web usado pelos domínios de phishing. |
| **500** | UDP | IKE (VPN) – *Encryption: False* | VPN não criptografada; pode ser usada para tráfego interno não protegido. |
| **7011** | TCP | **Sem banner identificado** | Possível serviço customizado (ex.: *C2* ou *backdoor*). Recomendado fingerprinting adicional. |

### 3.2 Vulnerabilidades (CVEs) associadas ao que foi identificado
| Serviço | Versão | CVE(s) relevantes | Impacto |
|---------|--------|-------------------|---------|
| OpenSSH | 7.6p1 | **CVE‑2018‑15473** (enumeration de usuários), **CVE‑2019‑6111** (denial‑of‑service via crafted packets), **CVE‑2020‑15778** (ciphers weak), **CVE‑2021‑41617** (auth bypass) | Elevação de privilégio, coleta de credenciais, DoS. |
| Apache 2.4.58 | 2.4.58 | **CVE‑2023‑25690** (path traversal), **CVE‑2023‑44487** (mod_status exposure) – ver se o servidor está atualizado. | Possível execução remota de código, vazamento de informações. |
| IKE (VPN) | - | **CVE‑2019‑14899** (IPsec IKEv2 DoS), **CVE‑2020‑16898** (Windows “Bad Neighbor”) – dependente da implementação, mas a falta de criptografia indica má configuração. | Interceptação de tráfego, uso como túnel para atividades maliciosas. |

> **Nota:** Não foram encontrados *CVE IDs* diretamente listados pelo Shodan; as vulnerabilidades acima foram inferidas a partir das versões dos softwares detectados.

---

## 4. Informações de Rede e Geográficas

| Campo | Valor |
|-------|-------|
| **IP** | 216.238.109.50 |
| **Hostname** | 216.238.109.50.vultrusercontent.com |
| **ASN** | **AS20473** – *Vultr Holdings, LLC* |
| **ISP** | **The Constant Company, LLC** |
| **Organização** | Vultr Holdings, LLC |
| **Provedor de Cloud** | **Vultr** |
| **Região Cloud** | **BR‑SP** (São Paulo, Brasil) |
| **Cidade** | Osasco |
| **Estado** | São Paulo |
| **País** | Brasil |
| **Latitude/Longitude** | -23.5325 / -46.7917 |
| **Timezone** | America/Sao_Paulo |
| **Data de Registro da Rede** | 2022‑01‑03 |
| **Última Visibilidade (Shodan)** | 2025‑10‑27 |

---

## 5. Recomendações

| Área | Ação recomendada |
|------|------------------|
| **Detecção & Bloqueio** | - Bloquear o IP nas firewalls de borda e nas listas de bloqueio de proxies. <br> - Incluir o IP em listas de bloqueio de Threat Intelligence (e.g., Spamhaus, Emerging Threats). |
| **Análise de Logs** | - Verificar logs de SSH ( `/var/log/auth.log` ) para tentativas de login, chaves aceitas e origem dos acessos. <br> - Analisar tráfego de IKE (porta 500) nos firewalls/IDS para detectar fluxos VPN não autorizados. |
| **Atualização de Software** | - Atualizar o OpenSSH para a versão mais recente (≥ 9.x) ou aplicar patches de segurança. <br> - Atualizar Apache para a última branch segura. |
| **Hardening** | - Desabilitar login root via SSH, usar chave pública/privada com passphrase forte. <br> - Configurar o IKE VPN com criptografia (AES‑256) e autenticação robusta (PSK forte ou certificados). |
| **Investigação de Domínios** | - Consultar feeds de Phishing (e.g., PhishTank, OpenPhish) para confirmar classificação dos domínios. <br> - Realizar análise de conteúdo das páginas (HTML/JS) em sandbox para identificar scripts maliciosos ou redirecionamentos. |
| **Malware / C2** | - Utilizar scanners de vulnerabilidade (Nessus, OpenVAS) para mapear possíveis backdoors na porta 7011. <br> - Se houver suspeita de *C2*, capturar tráfego de rede para análise de indicadores (IOCs). |
| **Responsável de Abuso** | - Notificar o provedor Vultr via <abuse@vultr.com> com evidências (logs, URLs de phishing). |
| **Monitoramento Contínuo** | - Configurar alertas no Shodan/Passive DNS para detectar novas portas ou alterações de banners. <br> - Usar serviços de *Passive DNS* (e.g., SecurityTrails) para acompanhar outros domínios que apontam para o mesmo IP. |
| **Legal / Compliance** | - Caso haja evidência de fraude contra usuários brasileiros, considerar notificar a Polícia Federal (CPf/Internet) e a Autoridade Nacional de Proteção de Dados (ANPD). |

---

### 📌 Conclusão
O IP **216.238.109.50** mostra um perfil típico de **infraestrutura de nuvem mal configurada e utilizada para hospedagem de sites de phishing**. A combinação de serviços expostos (SSH vulnerável, VPN sem criptografia e porta desconhecida) cria uma superfície de ataque considerável, facilitando tanto a **comprometimento interno** quanto o **uso como ponto de pivot** para outras atividades maliciosas. A rápida remediação (patches, hardening, bloqueio) e a notificação ao provedor são passos essenciais para mitigar o risco.