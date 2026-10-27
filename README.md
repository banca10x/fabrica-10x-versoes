# fabrica-10x-versoes
Versões prontas da Fábrica de Vídeos 10x (só instaladores, sem código)

## Como as versões são montadas (para o dono)

Os instaladores são montados aqui, pelo workflow **Montar o instalador** (Actions, disparo manual), porque os minutos de Actions de repositório público são grátis. O código-fonte continua no repositório privado `banca10x/fabrica-videos` e é baixado só durante o build.

Segredo necessário (Settings > Secrets and variables > Actions): **`FONTE_TOKEN`**, um token fine-grained com acesso **somente ao repositório `banca10x/fabrica-videos`** e a permissão **Contents: Read-only**. Nada mais: a Release é publicada com o `GITHUB_TOKEN` do próprio workflow.

O workflow **Componente de download** (yt-dlp + Deno) também mora aqui; a rotina diária está desligada até o ok do dono.
