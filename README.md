# ohttp
ohttp is a go http client

## usage
Get
```
    req := ohttp.InitSetttings()
    req.Timeout = 10 * time.Second
    req.IsAajx = true
    req.Referer = "https://www.abc.com"
    req.Cookies = cookie

    timestamp := util.GetTimestampMs()
    content, _, err := req.Get("https://www.abc.com/query?a=1&b=2&c=3")

    fmt.Println(content)
```

Post
```
    req := ohttp.InitSetttings()
    req.Timeout = 10 * time.Second
    req.IsAajx = true
    req.Referer = "https://www.abc.com"
    req.Cookies = cookie

    params := map[string]string{
        "itemId": "123",
        "price" : "456.00",
    }

    content, _, err := req.Post("https://www.abc.com/receive", params)
    if err != nil {
        return nil, err
    }

    fmt.Println(content)
```