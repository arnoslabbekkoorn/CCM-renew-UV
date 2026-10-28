Akamai Cloud certificate Manager Lets Encrypt certificate generation renewal  

This Script renews a lets Encrypt certificate lineage generation based on expiration date.

requires :  Acme production URL 
            Acme Public Account Key 
            Akamai CCM Lineage_ID
            .env file 

Flow : 1. Fetch Expiration
       2. If Expiration is below threshold f.e 7 days before expration 
       3  generate new CSR
       4. Send CSR to Lets Encrypt
       5. Fetch DNS challenge
       6. Create temporary Acme DNS records
       7. Validate DNS challenges
       8. Request Acme Order
       9. Fetch Signed certifiates and upload to CCM
       10. Promote certificte to staging and production. 
       
       
