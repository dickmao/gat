=========
 Install
=========

Google Cloud Preliminaries
==========================

Follow `docker install <https://docs.docker.com/engine/install>`_.

Follow `billing setup <https://cloud.google.com/compute/docs/quickstart-linux>`_.

Follow `gcloud install <https://cloud.google.com/sdk/gcloud#the_gcloud_cli_and_cloud_sdk>`_.

Follow `gcsfuse install <https://github.com/GoogleCloudPlatform/gcsfuse/blob/master/docs/installing.md>`_.

Create a service account just for ``gat``.

.. code-block:: shell-session

   PROJECT_ID=`gcloud config get-value project`
   NAME=gat-service-account
   EMAIL="${NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
   gcloud iam service-accounts create "${NAME}"
   gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
                   --member "serviceAccount:${EMAIL}" \
                   --role "roles/owner"
   mkdir -p ${XDG_CONFIG_HOME:-$HOME/.config}/gcloud
   gcloud iam service-accounts keys \
          create ${XDG_CONFIG_HOME:-$HOME/.config}/gcloud/${NAME}.json \
          --iam-account "${EMAIL}"

Enable some APIs:

.. code-block:: shell-session

   gcloud services enable cloudfunctions.googleapis.com
   gcloud services enable containerregistry.googleapis.com
   gcloud services enable pubsub.googleapis.com
   gcloud services enable storage-api.googleapis.com

The gat module
==============

.. code-block:: shell-session

   git clone git@github.com:dickmao/gat.git
   cd gat
   make install

This modifies your ``$HOME/.bashrc`` or ``$HOME/.zshrc``.  Start a new shell for the changes to take effect.

To receive email notifications of finished jobs, you need a `SendGrid <https://signup.sendgrid.com>`_ account.  Once you receive the SendGrid API Key, you also need to run `Single Sender Verification <https://sendgrid.com/docs/ui/sending-email/sender-verification/>`_.  Then configure ``gat`` with the SendGrid profile just verified.

.. code-block:: shell-session

   gat sendgrid --name [From Name] \
                --address [From Email Address] \
                --key [SendGrid API Key]
