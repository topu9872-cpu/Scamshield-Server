const API_KEY=process.env.VIRUSTOTAL_API_KEY!

export const checkUrlWithVirusTotal=async(url:string)=>{
    const response=await fetch("https://www.virustotal.com/api/v3/urls",{
        method:'POST',
        headers:{
            'x-apikey':API_KEY,
            'Content-Type':'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
            url
        })

    })
if(!response.ok) throw new Error('VirusTotal request failed')

   return await response.json()

}