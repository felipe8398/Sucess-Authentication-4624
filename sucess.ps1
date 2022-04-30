param ($User,$COMPUTERNAME,$BUSCA)
if ($User -like "*?*")
{
write-host "Realizando a busca por todas as autenticações com sucesso que partiram do Usuario: $USER"
Get-EventLog -LogName Security | ?{(4624) -contains $_.EventID }| %{
(new-object -Type PSObject -Property @{
TimeGenerated = $_.TimeGenerated
ClientIP = $_.Message -replace '(?smi).*Source Network Address:\s+([^\s]+)\s+.*','$1'
UserName = $_.Message -replace '(?smi).*\s\sAccount Name:\s+([^\s]+)\s+.*','$1'
UserDomain = $_.Message -replace '(?smi).*\s\sAccount Domain:\s+([^\s]+)\s+.*','$1'
LogonType = $_.Message -replace '(?smi).*Logon Type:\s+([^\s]+)\s+.*','$1'
WorkstationName = $_.Message -replace '(?smi).*\s\sWorkstation Name::*\s+([^\s]+)\s+.*','$1' 
})
} | sort TimeGenerated -Descending | Where-Object { $_.UserName -like "$USER" } | Format-Table -Property TimeGenerated,ClientIP,UserDomain,UserName,WorkstationName,LogonType -AutoSize | more
}
elseif ($COMPUTERNAME -like '*?*')
{
write-host "Realizando a busca por todas as autenticações com sucesso que partiram da workstation: $COMPUTERNAME"
Get-EventLog -LogName Security | ?{(4624) -contains $_.EventID }| %{
(new-object -Type PSObject -Property @{
TimeGenerated = $_.TimeGenerated
ClientIP = $_.Message -replace '(?smi).*Source Network Address:\s+([^\s]+)\s+.*','$1'
UserName = $_.Message -replace '(?smi).*\s\sAccount Name:\s+([^\s]+)\s+.*','$1'
UserDomain = $_.Message -replace '(?smi).*\s\sAccount Domain:\s+([^\s]+)\s+.*','$1'
LogonType = $_.Message -replace '(?smi).*Logon Type:\s+([^\s]+)\s+.*','$1'
WorkstationName = $_.Message -replace '(?smi).*\s\sWorkstation Name::*\s+([^\s]+)\s+.*','$1' 
})
} | sort TimeGenerated -Descending | Where-Object { $_.WorkstationName -like "$COMPUTERNAME" } | Format-Table -Property TimeGenerated,ClientIP,UserDomain,UserName,WorkstationName,LogonType -AutoSize | more
}
elseif ($BUSCA -match 'TUDO')
{
write-host "Realizando a busca por todas as autenticações com sucesso"
Get-EventLog -LogName Security | ?{(4624) -contains $_.EventID }| %{
(new-object -Type PSObject -Property @{
TimeGenerated = $_.TimeGenerated
ClientIP = $_.Message -replace '(?smi).*Source Network Address:\s+([^\s]+)\s+.*','$1'
UserName = $_.Message -replace '(?smi).*\s\sAccount Name:\s+([^\s]+)\s+.*','$1'
UserDomain = $_.Message -replace '(?smi).*\s\sAccount Domain:\s+([^\s]+)\s+.*','$1'
LogonType = $_.Message -replace '(?smi).*Logon Type:\s+([^\s]+)\s+.*','$1'
WorkstationName = $_.Message -replace '(?smi).*\s\sWorkstation Name::*\s+([^\s]+)\s+.*','$1' 
})
} | sort TimeGenerated -Descending | Format-Table -Property TimeGenerated,ClientIP,UserDomain,UserName,WorkstationName,LogonType -AutoSize | more
}
else 
{
write-host "VOCE PODE FAZER A BUSCA DE TRES FORMAS"
write-host "BUSCANDO PELO USUARIO: .\sucess.ps1 -USER Administrator"
write-host "BUSCANDO PELO NOME DA MÁQUINA QUE TENTOU AUTENTICAR: .\sucess.ps1 -COMPUTERNAME felipe-A520M-DS3H"
write-host "BUSCANDO POR TUDO: .\sucess.ps1 -BUSCA TUDO"
}
