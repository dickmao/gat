#!/bin/bash -ex

declare -a olds=()
for id in $(aws ec2 describe-images --filters "Name=name,Values=*packer-gat*" --query 'Images[*].[ImageId]' --output text) ; do
    olds+=($id)
done

if packer validate packer.json ; then
    packer build packer.json
fi

for id in "${olds[@]}"; do
    aws ec2 deregister-image --image-id $id
done
