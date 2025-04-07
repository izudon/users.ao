```
           JWT      OAuth2     redirect
/signup/  (pass)    required   save
/enter/   (pass)    required   save
/login/   (pass)    required   load
/plus/    required  required   save
/minus/   required  (no-need)  -
/agree/   required  (no-need)  -
```

```
01      2      3
12      3      4
/signup/google/AbCd12...?redirect=https%3A%2F%2Fapp-name.ao.incrage.com%2F
/enter/google?redirect=https%3A%2F%2Fapp-name.ao.incrage.com%2F
```
