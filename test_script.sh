#!/bin/bash
FLB_VERSION="v4.2.3"
FLB_SHORT=$(echo "${FLB_VERSION}" | sed 's/^v//')
echo "Short version is: ${FLB_SHORT}"
