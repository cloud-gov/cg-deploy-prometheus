#!/bin/bash

set -ex

lb_arns=()
lb_selector='.LoadBalancers[] | select(.LoadBalancerName | startswith($prefix)) | .LoadBalancerArn'
lbs=$(aws elbv2 describe-load-balancers)
for lb_arn in $(echo "${lbs}" | jq -r --arg prefix "${PREFIX}" "${lb_selector}"); do
  lb_arns+=("${lb_arn}")
done
next_token=$(echo "${lbs}" | jq -r '.NextToken // ""')
while [ -n "${next_token}" ]; do
  lbs=$(aws elbv2 describe-load-balancers --starting-token "${next_token}")
  for lb_arn in $(echo "${lbs}" | jq -r --arg prefix "${PREFIX}" "${lb_selector}"); do
    lb_arns+=("${lb_arn}")
  done
  next_token=$(echo "${lbs}" | jq -r '.NextToken // ""')
done

nlbs=0
ncerts=0
cert_names=""
cert_expirations=""
for lb_arn in "${lb_arns[@]}"; do
  lb_listener_arns=$(aws elbv2 describe-listeners --load-balancer-arn "${lb_arn}" \
      | jq -r ".Listeners[] | select(.Port == 443) | .ListenerArn")
  for lb_listener_arn in ${lb_listener_arns}; do
    nlbs=$((nlbs + 1))
    certs_listener=$(aws elbv2 describe-listener-certificates --listener-arn "${lb_listener_arn}")
    cert_names="${cert_names}"$'\n'"$(echo ${certs_listener} | jq -r '.Certificates[] | .CertificateArn'  | awk -F/ '{ print $NF }')"
      for cert_name in ${cert_names}; do
        cert_metadata=$(aws iam get-server-certificate --server-certificate-name ${cert_name})
        cert_date=$(echo "${cert_metadata}" | jq -r '.ServerCertificate | .ServerCertificateMetadata | .Expiration')
        cert_expiration=$(gdate --date "${cert_date}" +%s)
        cert_expirations="${cert_expirations}"$'\n'"domain_broker_certificate_expiration{certificate_name=\"${cert_name}\",listener_arn=\"${lb_listener_arn}\"} ${cert_expiration}"
      done
    ncerts_listener=$(echo "${certs_listener}" | jq -r ".Certificates | length")
    ncerts=$((ncerts + ncerts_listener))
  done
done

cert_expirations=$(echo "${cert_expirations}" | sort | uniq)
cat <<EOF | curl --data-binary @- "${GATEWAY_HOST}:${GATEWAY_PORT:-9091}/metrics/job/domain_broker/instance/${ENVIRONMENT}"
domain_broker_listener_count ${nlbs}
domain_broker_certificate_count ${ncerts}
${cert_expirations}
EOF
