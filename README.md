# sql_and_xss_crawler
### problem
> this is an integration project so it;s depend on populer scanners (sqlmap, xxstrike).
> the problem we sow is that this scanners acn scan one end point at time but a customer/non-production web app
> will need to get an over all scan aginst this most tow common vulns

### idea/soluation
so our idea is to find all end points from froms,urls,a tags. find how o send input to this endpoints,
and map this togither into an (reqerst)[./req.py]  then loop on this map and scan this endpoint tow times one for sql, and anther fo xss

u modify header.txt if u want to add cookie or extra headers \
just run `python3 main.py -u <url> --header_file header.txt`
