---
title: 'gat 0.0.1.dev documentation'
viewport: 'width=device-width, initial-scale=0.9, maximum-scale=0.9'
---

::: {.document}
::: {.sphinxsidebar role="navigation" aria-label="main navigation"}
::: {.sphinxsidebarwrapper}
[gat](index.html#document-index) {#gat .logo}
================================

### Navigation

[Contents:]{.caption-text}

-   [Install](index.html#document-install){.reference .internal}
-   [Usage](index.html#document-usage){.reference .internal}

::: {.relations}
### Related Topics

-   [Documentation overview](index.html#document-index)
:::
:::
:::

::: {.documentwrapper}
::: {.bodywrapper}
::: {.body role="main"}
::: {#welcome-to-gats-documentation .section}
Welcome to gat's documentation![¶](#welcome-to-gats-documentation "Permalink to this headline"){.headerlink}
============================================================================================================

[![Build
Status](https://github.com/dickmao/gat/workflows/CI/badge.svg)](https://github.com/dickmao/gat/actions){.reference
.external}

::: {.toctree-wrapper .compound}
[]{#document-install}

::: {#install .section}
Install[¶](#install "Permalink to this headline"){.headerlink}
--------------------------------------------------------------

::: {#google-cloud-preliminaries .section}
### Google Cloud Preliminaries[¶](#google-cloud-preliminaries "Permalink to this headline"){.headerlink}

Follow [docker
install](https://docs.docker.com/engine/install){.reference .external}.

Follow [billing
setup](https://cloud.google.com/compute/docs/quickstart-linux){.reference
.external}.

Follow [gcloud
install](https://cloud.google.com/sdk/gcloud#the_gcloud_cli_and_cloud_sdk){.reference
.external}.

Follow [gcsfuse
install](https://github.com/GoogleCloudPlatform/gcsfuse/blob/master/docs/installing.md){.reference
.external}.

Create a service account just for `gat`{.docutils .literal
.notranslate}.

::: {.highlight-shell-session .notranslate}
::: {.highlight}
    PROJECT_ID=`gcloud config get-value project`
    NAME=gat-service-account
    EMAIL="${NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
    gcloud iam service-accounts create "${NAME}"
    gcloud projects add-iam-policy-binding "${PROJECT_ID}" --member "serviceAccount:${EMAIL}" --role "roles/owner"
    mkdir -p ${XDG_CONFIG_HOME:-$HOME/.config}/gcloud
    gcloud iam service-accounts keys create ${XDG_CONFIG_HOME:-$HOME/.config}/gcloud/${NAME}.json --iam-account "${EMAIL}"
:::
:::

Enable some APIs:

::: {.highlight-shell-session .notranslate}
::: {.highlight}
    gcloud services enable cloudfunctions.googleapis.com
    gcloud services enable containerregistry.googleapis.com
    gcloud services enable pubsub.googleapis.com
    gcloud services enable storage-api.googleapis.com
:::
:::
:::

::: {#the-gat-module .section}
### The gat module[¶](#the-gat-module "Permalink to this headline"){.headerlink}

::: {.highlight-shell-session .notranslate}
::: {.highlight}
    git clone git@github.com:dickmao/gat.git
    cd gat
    make install
:::
:::

This modifies your `$HOME/.bashrc`{.docutils .literal .notranslate} or
`$HOME/.zshrc`{.docutils .literal .notranslate}, so start a new shell
for the changes to take effect.

To receive email notifications of finished jobs, you need a
[SendGrid](https://signup.sendgrid.com){.reference .external} account.
Once you receive the SendGrid API Key, you also need to run [Single
Sender
Verification](https://sendgrid.com/docs/ui/sending-email/sender-verification/){.reference
.external}. Then configure `gat`{.docutils .literal .notranslate} with
the SendGrid profile just verified.

::: {.highlight-shell-session .notranslate}
::: {.highlight}
    gat sendgrid --name [From Name] --address [From Email Address] --key [SendGrid API Key]
:::
:::
:::
:::

[]{#document-usage}

::: {#usage .section}
Usage[¶](#usage "Permalink to this headline"){.headerlink}
----------------------------------------------------------

As \_experiments\_ are implemented as git \_worktrees\_, we use the
terms interchangeably.

::: {#creating-experiments .section}
### Creating experiments[¶](#creating-experiments "Permalink to this headline"){.headerlink}

Start in the directory of your git project.

::: {.highlight-shell-session .notranslate}
::: {.highlight}
    gat create eta0.3
:::
:::
:::
:::
:::
:::

::: {#indices-and-tables .section}
Indices and tables[¶](#indices-and-tables "Permalink to this headline"){.headerlink}
====================================================================================

-   [[Index]{.std .std-ref}](genindex.html){.reference .internal}
-   [[Module Index]{.std .std-ref}](py-modindex.html){.reference
    .internal}
-   [[Search Page]{.std .std-ref}](search.html){.reference .internal}
:::
:::
:::
:::

::: {.clearer}
:::
:::

::: {.footer}
©2020, The Authors. \| Powered by [Sphinx 1.8.5](http://sphinx-doc.org/)
& [Alabaster 0.7.8](https://github.com/bitprophet/alabaster)
:::

[![Fork me on
GitHub](https://s3.amazonaws.com/github/ribbons/forkme_right_darkblue_121621.png){.github}](https://github.com/dickmao/gat){.github}
