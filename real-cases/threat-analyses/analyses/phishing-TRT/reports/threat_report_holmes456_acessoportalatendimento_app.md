# Relatório de Threat Intelligence – Domínio **holmes456.acessoportalatendimento.app**

> **Fonte dos dados**: WHOIS (parcial – via VirusTotal), VirusTotal, Urlscan.io, DNS (public DNS resolver 172.64.34.100), cabeçalhos HTTP via cURL, AlienVault OTX, documentação de certificado SSL/TLS.  
> **Timestamp da Análise**: 2026-01-14T11:27:02.154084.  

---

## 1. Resumo Executivo
O sub‑domínio **holmes456.acessoportalatendimento.app** resolve para dois endereços IPv4 pertencentes ao provedor de CDN **Cloudflare** (AS13335 – Cloudflare, Inc.) e dispõe de registros AAAA de Cloudflare. Não há indícios de malignidade nos scanners tradicionais – o *last_analysis_stats* do VirusTotal mostra **0 malicious / 0 suspicious** e 93 resultados “undetected”. Contudo, o domínio está protegido por **HTTPS com certificado emitido pela Google Trust Services** (válido até 02 out 2025) e responde ao HTTP‑GET com **403 Forbidden** (Cloudflare). Não foram encontrados **pulses** no AlienVault OTX.  

Apesar da classificação como “benigno”, a combinação de:  

* uso de **sub‑domínio aleatório** (`holmes456`) dentro de um domínio de nível 2 (`acessoportalatendimento.app`),  
* hospedagem em **CDN/edge** (Cloudflare) que permite rápido provisionamento de IP’s e mascaramento de origem,  
* ausência de conteúdo público (403)  

sugere que o sub‑domínio pode estar sendo usado como **infraestrutura de apoio (C2, entrega de payloads, redirecionamento)** por agentes maliciosos que se aproveitam da reputação neutra da CDN. Recomenda‑se tratá‑lo como **risco médio‑alto** até que novas evidências o classifiquem como benigno ou malicioso.

---

## 2. Análise de Comportamento
| Fonte | Evidência | Interpretação |
|-------|-----------|---------------|
| **VirusTotal** | 0 malicious, 0 suspicious, 93 undetected; certificado TLS válido (Google Trust Services) | Nenhum mecanismo de AV detectou atividade; a presença de certificado válido indica tentativa de **legitimação** da comunicação. |
| **Urlscan.io** (5 variações de scans) | Todas as execuções apontam para o mesmo IP `104.21.7.199` (Cloudflare) e `172.67.156.69` (Cloudflare); tamanho de página pequeno (≈ 78 bytes) e requisições limitadas | Indicador de **endpoint de “landing page” mínima**, possivelmente usada como *beacon* ou *redirect* para outros recursos maliciosos. |
| **DNS** | A‑records múltiplos (2 IPv4) + 2 AAAA (IPv6) com TTL = 300 s | Resolução rápida e rotativa, típica de serviços de CDN que podem ser usados para **esconder a origem real**. |
| **cURL (HTTP)** | Resposta “403 Forbidden” – servidor “cloudflare” | Bloqueio de acesso direto ao recurso, indicando que o domínio pode ser **acessado apenas via referências internas** (ex.: scripts, malware que já conhece caminhos/parametros). |
| **AlienVault OTX** | `pulses: []` (nenhum) | Ainda não inserido em feeds de inteligência publica, mas ausência de informação **não elimina** uso malicioso. |
| **WHOIS (via VT)** | Registrado em 2025‑04‑29 por “Tucows” (registrar); registrante anonimizado em Saint Kitts and Nevis | Uso de registrador de baixo custo e anonimato típico de **infraestrutura de suporte a campanhas**. |

### Táticas/Procedimentos (ATT&CK) possíveis
- **T1071 – Application Layer Protocol (HTTP/HTTPS)** – comunicação via Cloudflare.
- **T1041 – Exfiltration Over Command and Control Channel** – uso de sub‑domínio como “canais covertos”.
- **T1105 – Ingress Tool Transfer** – entrega de arquivos pequenos (ex.: scripts de bootstrap) por meio de página 403/redirect.
- **T1566.002 – Phishing – Link** – domínios de “acessoportalatendimento.app” podem ser inseridos em e‑mails de suporte falsos.

---

## 3. Informações de Rede e Geográficas

| Campo | Valor |
|------|-------|
| **ASN** | **AS13335 – Cloudflare, Inc.** (para ambos os IPv4/IPv6) |
| **ISP / Provedor** | Cloudflare, Inc. (serviço de CDN / WAF) |
| **Localização dos IPs** | **Estados‑Unidos** (registrado em *San Francisco, CA* – localização típica da Cloudflare; a CDN possui presença global) |
| **Endereços IPv4** | 104.21.7.199, 172.67.156.69 |
| **Endereços IPv6** | 2606:4700:3032::6815:7c7, 2606:4700:3034::ac43:9c45 |
| **Registros DNS** | A: 104.21.7.199, 172.67.156.69  <br> AAAA: 2606:4700:3032::6815:7c7, 2606:4700:3034::ac43:9c45 |
| **Certificado TLS** | Emitido por **Google Trust Services** (CN: acessoportalatendimento.app), validade 04‑jul‑2025 → 02‑out‑2025, algoritmo ECDSA‑P‑256, SHA‑256. |
| **WHOIS (domínio nível 2)** | `acessoportalatendimento.app` – registro 2025‑04‑29, registrar **Tucows**, registrante anonimizado (Saint Kitts and Nevis). |

---

## 4. Domínios e IPs Relacionados
| Tipo | Valor | Observação |
|------|-------|------------|
| **Domínio pai** | `acessoportalatendimento.app` | Registrado por Tucows; pode servir como “landing zone” para vários sub‑domínios aleatórios. |
| **Sub‑domínios observados** | `holmes456.acessoportalatendimento.app` | Único sub‑domínio encontrado nos dados. |
| **IPs IPv4** | 104.21.7.199 (Cloudflare) <br> 172.67.156.69 (Cloudflare) | Ambos pertencem ao mesmo ASN (AS13335). |
| **IPs IPv6** | 2606:4700:3032::6815:7c7 <br> 2606:4700:3034::ac43:9c45 | Também da Cloudflare. |
| **Domínios “sister” (exemplos de buscas públicas)** | Não foram identificados outros sub‑domínios no escopo, porém a estrutura do registro permite a criação de infinitos sub‑domínios “on‑the‑fly”. |

> **Nota:** Não foram encontradas referências a domínios externos (C2, phishing) diretamente associadas a este sub‑domínio nos feeds consultados.

---

## 5. Recomendações de Ações de Investigação
1. **Monitoramento DNS interno** – Registre todas as consultas ao FQDN `holmes456.acessoportalatendimento.app` (e ao domínio pai) nos seus servidores DNS ou proxy DNS. Gere alertas para resoluções fora do horário comercial ou para trocas de IPs rápidas.  
2. **Análise de fluxo de rede** – Correlacione logs de firewall/proxy para tráfego HTTP/HTTPS que contenha o host acima. Busque por padrões de *user‑agent* ou *referer* incomuns.  
3. **Enriquecimento de IPs** – Consulte bases de inteligência adicionais (Passive DNS, IPINTEL, Shodan) para validar se os IPs da Cloudflare foram usados em **malwares conhecidos** ou *phishing kits*.  
4. **Sandbox de URLs** – Submeta a URL completa (`https://holmes456.acessoportalatendimento.app/`) a um sandbox (e.g., Cuckoo, Hybrid Analysis) para observar se há redirecionamentos, download de binários ou chamadas ao C2.  
5. **Verificação de certificado** – Embora emitido por Google Trust Services, valide a cadeia completa (CRL/OCSP) para garantir que não há *certificate pinning* ou uso de certificados comprometidos.  
6. **Bloqueio defensivo** – Enquanto a análise está em andamento, considere **bloquear temporariamente** o domínio ou seus IPs no firewall/UTM para endpoints críticos, especialmente se houver incidentes de phishing ou C2 detectados.  
7. **Inteligência de Threat Hunting** – Procure por hashes, strings ou “user‑agents” associados a campanhas que empregam *Cloudflare‑based* C2 (ex.: “MikroTik‑C2”, “Emotet‑cloud”).  
8. **Revisão de políticas de email** – Caso o domínio apareça em relatórios de phishing (ex.: “Microsoft Phishing Collection”), inclua regras de filtro para bloquear mensagens que contenham links para `*.acessoportalatendimento.app`.  

---

## 6. Conclusão
O sub‑domínio **holmes456.acessoportalatendimento.app** não apresenta indicadores diretos de comprometimento nos principais motores de AV, mas sua **infraestrutura baseada em Cloudflare**, a **ausência de conteúdo visível** (403) e o **uso de um nome de sub‑domínio aleatório** são característicos de **infraestruturas de apoio a atividades maliciosas** (C2, entrega de payloads, redirecionamento para sites de phishing).  

Dada a possibilidade de uso como “capa” por atores ameaçadores, recomenda‑se **tratar o domínio como risco médio‑alto**, implementar monitoramento ativo e, se necessário, bloqueio preventivo, enquanto se aprofundam as investigações de tráfego e de eventuais indicadores associados.