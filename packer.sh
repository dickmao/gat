#!/bin/bash -ex

for id in $(aws ec2 describe-images --filters "Name=name,Values=*packer-gat*" --query 'Images[*].[ImageId]' --output text) ; do
    aws ec2 deregister-image --image-id $id
done

if packer validate packer.json ; then
    packer build packer.json
fi
