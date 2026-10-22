# php2shell-check

Confere se o PHP instalado já tem a correção do PHP2Shell (CVE-2026-109618 e CVE-2026-109619) e atualiza os pacotes do runtime pelo apt.

O script não testa a falha, não envia requisição e não muda `memory_limit`. A correção é instalar o PHP novo e reiniciar o worker.

## Releases oficiais

Publicadas em 21 de outubro de 2026. Qualquer versão anterior do mesmo ramo está vulnerável.

| Ramo | Primeira release corrigida |
| --- | --- |
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

O php.net não publicou release nova para 8.1 ou anterior. Nesses ramos o número do PHP continua o mesmo (por exemplo 7.4.33). O que muda é a revisão do pacote. O script só aceita essa correção de mantenedor quando o changelog cita o CVE, ou quando o pacote vem do `deb.sury.org` com a revisão de 21 de outubro de 2026 ou mais nova:

| Pacote | Revisão mínima no deb.sury.org |
| --- | --- |
| 5.6.40 | 104 |
| 7.0.33 | 92 |
| 7.1.33 | 80 |
| 7.2.34 | 66 |
| 7.3.33 | 35 |
| 7.4.33 | 31 |
| 8.0.30 | 25 |
| 8.1.34 | 9 |

Esse backport não é a mesma correção das releases 8.2.35+. O resultado aparece como `backport`, não como `corrigido`.

## Uso

```bash
git clone https://github.com/jeanccoelho/php2shell-check.git
cd php2shell-check
./php2shell-check.sh
sudo ./php2shell-check.sh --apply
```

`--apply` atualiza somente pacotes já instalados do runtime (`php8.3-cli`, `php8.3-fpm`, `libapache2-mod-php8.3` e os equivalentes de cada ramo). Não troca a aplicação de container. Se achar PHP dentro de um container em execução, imprime a imagem e a versão; a troca da tag fica com quem mantém esse container.

`--use-sury`, junto com `--apply`, adiciona `ppa:ondrej/php` só se depois do upgrade o PHP ainda estiver sem correção comprovada. Esse PPA é de terceiros (Ondřej Surý, no Launchpad). Sem essa flag o script não mexe em fonte de pacote.

`--strict` também termina com erro quando o único PHP encontrado está em `backport`.

Containers não são recriados. Para imagem oficial do Docker, use uma tag da tabela de cima (`php:8.3.36`, `php:8.4.27`, `php:8.2.35` ou `php:8.5.12`). A imagem oficial não recebe correção para 8.1 ou anterior.

## O que cada linha significa

- `corrigido` — release oficial 8.2.35, 8.3.36, 8.4.27, 8.5.12 ou mais nova do mesmo ramo.
- `backport` — ramo antigo com o pacote do mantenedor que cita a correção.
- `vulneravel` — a versão ou a revisão do pacote é anterior à correção publicada.
- `desconhecido` — não há como comprovar (por exemplo um ramo 8.6 sem o CVE no changelog). Conta como pendência.
- `nao_afetado` — anterior a 5.4, fora do intervalo publicado.

Código de saída `0` quando não há `vulneravel` nem `desconhecido`. Código `1` quando ainda há. Código `2` quando o comando foi usado errado ou o apt falhou.

## Fontes

- Tabela de releases em [php2shell.com](https://www.php2shell.com/)
- Orientação de atualização da [Sansec](https://sansec.io/research/php2shell)
- Pacotes de 21 de outubro de 2026 no [PPA Ondřej Surý](https://launchpad.net/~ondrej/+archive/ubuntu/php)
- Mapa de backport por distribuição em [ma.ttias.be](https://ma.ttias.be/php-cve-2026-109618-patch/)

## English

Checks installed PHP against the PHP2Shell fixes and can upgrade already installed apt packages. It does not exploit the bug. Official fixed releases are 8.2.35, 8.3.36, 8.4.27 and 8.5.12. Older branches keep the same PHP version number; the package revision is what changes. Run `./php2shell-check.sh` to report, and `sudo ./php2shell-check.sh --apply` to upgrade.
