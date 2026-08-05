const API_KEY=process.env.GOOGLE_SAFE_BROWSING_API_KEY

export const checkUrlWithGoogle=async(url:string)=>{
    const response=await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`,{
        method:'POST',
        headers: {
            'content-type': 'application/json'
        },
        body:JSON.stringify({
            client:{
                clientId:'scemshield',
                clientVersion:'1.0.0'
            },
            theatInfo:{
             threatType:   [
                'MALWARE',
                'SOCIAL_ENGINEERING',
                'UNWANTED_SOFTWARE',
               ' POTENTIALLY_HARMFUL_APPLICATON'
            ],
            platformType:['ANY_PLATFORM'],
            threatEntrytypes:['URL'],
            threatEntries:[{url}]
            }
        })
    })
    return await response.json()
     
}