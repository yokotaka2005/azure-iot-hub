# IoT hub用　SAS作成スクリプト
# 参考ドキュメント https://docs.microsoft.com/ja-jp/azure/iot-hub/iot-hub-devguide-security#security-tokens

# 有効期間 (秒）
$expiryInSecond = 3600
# DeviceのPrimary Key
$key = "uRr6Fv83XUeQuoJLfwXV4AaWolox30byvY1Jz8YzBF4="
# IoT hubのURI
$resourceUri = "MQTT-TEST-YOKOI.azure-devices.net/devices/Dev0"
# セキュリティポリシー　基本的に設定なし、空欄
$policyName = ""

# 以下メイン処理
$fromEpochStart = [System.DateTime]::UtcNow - (New-Object DateTime(1970, 1, 1))

$expiry = [System.Convert]::ToString( [int]$fromEpochStart.TotalSeconds + $expiryInSecond )

$stringToSign = [System.Net.WebUtility]::UrlEncode($resourceUri) + "`n" + $expiry

$temp = [System.Convert]::FromBase64String($key)

$hmac = New-Object -TypeName System.Security.Cryptography.HMACSHA256 -argumentList @(,$temp)

$signature = [System.Convert]::ToBase64String($hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($stringToSign)))

$token = [string]::Format([CultureInfo]::InvariantCulture, "SharedAccessSignature sr={0}&sig={1}&se={2}", [System.Net.WebUtility]::UrlEncode($resourceUri), [System.Net.WebUtility]::UrlEncode($signature), $expiry)

if(-not [string]::IsNullOrEmpty($policyName))
{
    $token += "&skn=" + $policyName
}

echo $token