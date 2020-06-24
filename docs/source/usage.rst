=======
 Usage
=======

GPUs
====

*Nota bene* you must explicitly `request a quota increase <https://cloud.google.com/compute/quotas#requesting_additional_quota>`_.

Establish a baseline
====================

Assume a training task under git.  Create a `Dockerfile <https://docs.docker.com/get-started/part2/#sample-dockerfile>`_, e.g.,
::

   FROM tensorflow/tensorflow
   COPY ./train.py .
   CMD python train.py

Test your ``Dockerfile`` with

.. code-block:: shell-session

   gat run-local

Now run the task in Compute Engine.

.. code-block:: shell-session

   gat run-remote

Tail the output of your task.

.. code-block:: shell-session

   gat log -f

Inspect results in the newly created ``run-local`` and ``run-remote`` directories.

Creating experiments
====================

Suppose we want to change the learning rate :math:`\eta` to 0.3.

.. code-block:: shell-session

   gat create eta0.3

Modify the code to effect the change, and rerun ``gat run-local`` or ``gat run-remote``.

Navigating between experiments
==============================

To list all experiments,

.. code-block:: shell-session

   gat list

To return to the baseline,

.. code-block:: shell-session

   gat master

To return to an experiment,

.. code-block:: shell-session

   gat eta0.3
