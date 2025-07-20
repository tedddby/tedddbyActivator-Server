<?php
if(!isset($_POST['activation-info']) || empty($_POST['activation-info'])) { exit('403'); }

else
{
    function strip_data($key, $string) {
$beginning = '<key>'.$key.'</key>';
$end = '</data>';
$beginningPos = strpos($string, $beginning);
$tmpstring = substr($string, $beginningPos);
$endPos = strpos($tmpstring, $end);
if ($beginningPos === false || $endPos === false) {
    return $string;
}
$textToDelete = substr($string, $beginningPos, ($endPos + strlen($end)) );
file_put_contents('delete', $textToDelete);
return strip_data($key, str_replace($textToDelete, '', $string)); // recursion to ensure all occurrences are replaced
}
function strToHex($string){
  $hex = '';
  for ($i=0; $i<strlen($string); $i++){
    $ord = ord($string[$i]);
    $hexCode = dechex($ord);
    $hex .= substr('0'.$hexCode, -2);
  }
  return strToUpper($hex);
}

function hexToStr($hex){
  $string='';
  for ($i=0; $i < strlen($hex)-1; $i+=2){
    $string .= chr(hexdec($hex[$i].$hex[$i+1]));
  }
  return $string;
}



	$activation = $_POST['activation-info'];
	$ticketID = $_POST['activation-info'];
	$encodedrequest = new DOMDocument;
	$encodedrequest->loadXML($activation);

	$activationDecoded= base64_decode($encodedrequest->getElementsByTagName('data')->item(0)->nodeValue);

	$decodedrequest = new DOMDocument;
	$decodedrequest->loadXML($activationDecoded);
	$nodes = $decodedrequest->getElementsByTagName('dict')->item(0)->getElementsByTagName('*');
	    
    file_put_contents('info', $activation);
	for ($i = 0; $i < $nodes->length - 1; $i=$i+2)
	{
	  ${$nodes->item($i)->nodeValue} = preg_match('/(true|false)/', $nodes->item($i + 1)->nodeName) ? $nodes->item($i + 1)->nodeName : $nodes->item($i + 1)->nodeValue;
	    switch ($nodes->item($i)->nodeValue)
	    {
        case "ActivationState": $activationState = $nodes->item($i + 1)->nodeValue; break;
        case "ActivationRandomness": $activationRandomness = $nodes->item($i + 1)->nodeValue; break;
        case "DeviceCertRequest": $deviceCertRequest = $nodes->item($i + 1)->nodeValue; break;
        case "DeviceClass": $deviceClass = $nodes->item($i + 1)->nodeValue; break;
        case "BasebandChipID": $BasebandChipID = $nodes->item($i + 1)->nodeValue; break;
        case "InternationalMobileEquipmentIdentity": $imei = $nodes->item($i + 1)->nodeValue; break;
        case "MobileEquipmentIdentifier": $meid = $nodes->item($i + 1)->nodeValue; break;
        case "ProductType": $productType = $nodes->item($i + 1)->nodeValue; break;
        case "ProductVersion": $productVersion = $nodes->item($i + 1)->nodeValue; break;
        case "OSType": $OSType = $nodes->item($i + 1)->nodeValue; break;
        case "WifiAddress": $wifi = $nodes->item($i + 1)->nodeValue; break;
        case "UniqueChipID": $ecid = $nodes->item($i + 1)->nodeValue; break;
        case "ChipID": $chipID = $nodes->item($i + 1)->nodeValue; break;
        case "BluetoothAddress": $BluetoothAddress = $nodes->item($i + 1)->nodeValue; break;
        case "UniqueDeviceID": $uniqueDeviceID = $nodes->item($i + 1)->nodeValue; break;
        case "SerialNumber": $serialNumber = $nodes->item($i + 1)->nodeValue; break;
        case "BasebandMasterKeyHash": $BasebandMasterKeyHash = $nodes->item($i + 1)->nodeValue; break;
        case "BasebandSerialNumber": $BasebandSerialNumber = $nodes->item($i + 1)->nodeValue; break;
        case "BasebandChipID": $BasebandChipID = $nodes->item($i + 1)->nodeValue; break;
        case "RegulatoryModelNumber": $RegulatoryModelNumber = $nodes->item($i + 1)->nodeValue; break;
        case "ModelNumber": $ModelNumber = $nodes->item($i + 1)->nodeValue; break;
        case "BuildVersion": $BuildVersion = $nodes->item($i + 1)->nodeValue; break;
        case "mac_fg": $mac_fg = $nodes->item($i + 1)->nodeValue; break;
        case "SIMStatus": $SIMStatus = $nodes->item($i + 1)->nodeValue; break;
        case "UIKCertification": $UIKCertification = $nodes->item($i + 1)->nodeValue; break;
        case "InternationalMobileSubscriberIdentity": $imsi = $nodes->item($i + 1)->nodeValue; break;
        case "IntegratedCircuitCardIdentity": $iccid = $nodes->item($i + 1)->nodeValue; break;
		}
	}
	
	if(!file_exists("ActivationFiles/".$serialNumber."/"))
	{
		mkdir("ActivationFiles/".$serialNumber."/", 0777, true);
	}
	    $curl = curl_init();
    $activation = strip_data('FairPlaySignature',$activation);
    $activation = strip_data('FairPlayCertChain',$activation);
    $activation = strip_data('signActRequest',$activation);
    $activation = strip_data('serverKP',$activation);
    $activation = '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">'."\n".$activation."\n".'</plist>';
    error_log($activation);
    
curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);

    curl_setopt_array($curl, array(
  CURLOPT_URL => 'https://tbsc.apple.com/oob/vend',
  CURLOPT_RETURNTRANSFER => true,
  CURLOPT_ENCODING => '',
  
  CURLOPT_MAXREDIRS => 10,
  CURLOPT_TIMEOUT => 0,
  CURLOPT_FOLLOWLOCATION => true,
  CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
  CURLOPT_CUSTOMREQUEST => 'POST',
      CURLOPT_POSTFIELDS => $activation,
                CURLOPT_HTTPHEADER => array(
        'User-Agent: macOS Device Activator (MobileActivation-592.40.37) - mobileactivationd',
        'Content-Type: application/xml'
      ),
    ));

    $response = curl_exec($curl);

    curl_close($curl);
    error_log($response);
    $UDC = base64_encode($response);
	
	
	function GETWILDCARDTICKETGSM($BasebandMasterKeyHash, $BasebandChipID, $BasebandSerialNumber, $BuildVersion, $productType, $productVersion, $RegulatoryModelNumber,$activationRandomness, $serialNumber)
	{
		require('infos/InfoWildcard.php');
				$ActivationInfoXML64 = base64_encode($ActivationInfoXML);

				$private = file_get_contents("keys/key_wildcard.pem");
				
				$FairPlayCertChain = base64_encode(file_get_contents('FairplayCerts/FairPlayCertChain.der'));

				$pkeyid = openssl_pkey_get_private($private);
				openssl_sign($ActivationInfoXML, $signature, $pkeyid, 'sha1WithRSAEncryption');
				openssl_free_key($pkeyid);
				$FairPlaySignature = base64_encode($signature);

				require('infos/FinalInfoWildcard.php');
			$url = 'https://albert.apple.com/deviceservices/deviceActivation';
			$data_info=urlencode($data);
			$post_data ="activation-info=".$data_info;
			$ch = curl_init(); 
			curl_setopt($ch, CURLOPT_URL , $url ); 
			curl_setopt($ch, CURLOPT_RETURNTRANSFER , 1); 
			curl_setopt($ch, CURLOPT_TIMEOUT , 60); 
			curl_setopt($ch, CURLOPT_VERBOSE, 0);
			curl_setopt($ch, CURLOPT_HEADER, 0);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array("Host: albert.apple.com", "Content-Type: application/x-www-form-urlencoded", "Connection: keep-alive", "Accept: *", "Accept-Language: en-US", "Content-Length: ".strlen($post_data), "User-Agent: iTunes/12.11.3 (Windows; Microsoft Windows 10 x64 (Build 19042); x64) AppleWebKit/7611.1022.4001.1 (dt:2)"));
			curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
			curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
			curl_setopt($ch, CURLOPT_USERAGENT , "iOS Device Activator (MobileActivation-353.200.48)" );
			curl_setopt($ch, CURLOPT_POST , 1); 
			curl_setopt($ch, CURLOPT_POSTFIELDS , $post_data);  

			$xml_response = curl_exec($ch); 

			if (curl_errno($ch)) { 
				$error_message = curl_error($ch); 
				$error_no = curl_errno($ch);

				echo "error_message: " . $error_message . "<br>";
				echo "error_no: " . $error_no . "<br>";
			}
			curl_close($ch);
			$Stage1 = explode("<key>AccountToken</key>", $xml_response)[1];
			$Stage2 = explode("<data>", $Stage1)[1];
			$Stage3 = explode("</data>", $Stage2)[0];
			$Wildcard = explode('"WildcardTicket" = "', base64_decode($Stage3))[1];
			$Ticket = explode('";', $Wildcard)[0];
			if($Ticket != null)	{
				return $Ticket;
			}
			else	{				
				$Stage1 = explode("<key>AccountToken</key>", $xml_response)[1];
				$Stage2 = explode("<data>", $Stage1)[1];
				$Stage3 = explode("</data>", $Stage2)[0];
				$Wildcard = explode('"ActivationTicket" = "', base64_decode($Stage3))[1];
				$Ticket = explode('";', $Wildcard)[0];
				return $Ticket;
			}				
			file_put_contents('ActivationFiles/'.$serialNumber.'/WildcardTicket.pem', $Ticket);
	}
			function FPDC_ALL($activationRandomness,$deviceCertRequest,$uniqueDeviceID,$BuildVersion,$DeviceClass,$DeviceVariant,$ModelNumber,$OSType,$productType,$ProductVersion,$RegulatoryModelNumber,$UniqueChipID, $serialNumber)
			{

				$ActivationInfoXML = '<?xml version="1.0" encoding="UTF-8"?>
				<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
				<plist version="1.0">
				<dict>
					<key>ActivationRequestInfo</key>
					<dict>
						<key>ActivationRandomness</key>
						<string>'.$activationRandomness.'</string>
						<key>ActivationState</key>
						<string>Unactivated</string>
						<key>FMiPAccountExists</key>
						<true/>
					</dict>
					<key>BasebandRequestInfo</key>
					<dict>
						<key>ActivationRequiresActivationTicket</key>
						<true/>
						<key>BasebandActivationTicketVersion</key>
						<string>V2</string>
						<key>BasebandChipID</key>
						<integer>7282913</integer>
						<key>BasebandMasterKeyHash</key>
						<string>AEA5CCE143668D0EFB4CE1F2C94C966A6496C6AA</string>
						<key>BasebandSerialNumber</key>
						<data>
						NE5Ksw==
						</data>
						<key>InternationalMobileEquipmentIdentity</key>
						<string>358832055421543</string>
						<key>SIMStatus</key>
						<string>kCTSIMSupportSIMStatusNotInserted</string>
						<key>SupportsPostponement</key>
						<true/>
						<key>kCTPostponementInfoPRIVersion</key>
						<string>0.1.141</string>
						<key>kCTPostponementInfoPRLName</key>
						<integer>0</integer>
						<key>kCTPostponementInfoServiceProvisioningState</key>
						<false/>
					</dict>
					<key>DeviceCertRequest</key>
					<data>
					'.$deviceCertRequest.'
					</data>
					<key>DeviceID</key>
					<dict>
						<key>SerialNumber</key>
						<string>FCHP606DG07R</string>
						<key>UniqueDeviceID</key>
						<string>'.$uniqueDeviceID.'</string>
					</dict>
					<key>DeviceInfo</key>
					<dict>
						<key>BuildVersion</key>
						<string>'.$BuildVersion.'</string>
						<key>DeviceClass</key>
						<string>'.$DeviceClass.'</string>
						<key>DeviceVariant</key>
						<string>'.$DeviceVariant.'</string>
						<key>ModelNumber</key>
						<string>'.$ModelNumber.'</string>
						<key>OSType</key>
						<string>'.$OSType.'</string>
						<key>ProductType</key>
						<string>'.$productType.'</string>
						<key>ProductVersion</key>
						<string>'.$ProductVersion.'</string>
						<key>RegionCode</key>
						<string>IP</string>
						<key>RegionInfo</key>
						<string>IP/A</string>
						<key>RegulatoryModelNumber</key>
						<string>'.$RegulatoryModelNumber.'</string>
						<key>UniqueChipID</key>
						<integer>'.$UniqueChipID.'</integer>
					</dict>
					<key>RegulatoryImages</key>
					<dict>
						<key>DeviceVariant</key>
						<string>'.$DeviceVariant.'</string>
					</dict>
					<key>UIKCertification</key>
					<dict>
						<key>BluetoothAddress</key>
						<string>bc:4c:c4:14:58:ac</string>
						<key>BoardId</key>
						<integer>14</integer>
						<key>ChipID</key>
						<integer>35152</integer>
						<key>EthernetMacAddress</key>
						<string>bc:4c:c4:14:58:ad</string>
						<key>UIKCertification</key>
						<data>
						MIICxjCCAm0CAQEwADCB2QIBATAKBggqhkjOPQQDAgNHADBEAiBOmykQ378M
						lvcKVkyjlHoYwKN8/WK/lHGv2zscJxnE+AIgN9zrZRpE0K7RZuZtruXkgFxV
						iM4SXByiyOPFmBdcy+MwWzAVBgcqhkjOPQIBoAoGCCqGSM49AwEHA0IABFNT
						gwNJnJnk05h2j2K9p75U96PvOBiti2J0nQNXeKWGKizCqergjKtHZqAtVBsX
						mdd3311pxQ75CsX3EUaznAagCgQIYWNzc0gAAACiFgQUfYSpUwwmRfMbGkRA
						Ps1aKCLT0dwwgcICAQEwCgYIKoZIzj0EAwIDSAAwRQIhAPDzRlZqRnm9wRmT
						1oIy5sh/AbDHSQVmitgH9NoCpoctAiB9+1hOM8Zeb1htQV8s81Xg0aou/86P
						PveOu9TIzYQNnDBbMBUGByqGSM49AgGgCgYIKoZIzj0DAQcDQgAESTAiT/2L
						1L1+0JBiUSGPumizG+wQp12JUM0T80UqWbvEE9ljAk676/zhKQBjl38/Sn06
						yO2EABYoYBIlgEi0ZKAKBAggc2tzAgAAAKCBxDCBwQIBATAKBggqhkjOPQQD
						AgNHADBEAiAtvdWemPKvE6kfMpY9pUYuvJcXbznA/oVLeEXPbzXtTgIgCBJP
						dGxZs0OZLgdfNAwJuxa+1dqcFgV1LDen2Gi9eM8wWzAVBgcqhkjOPQIBoAoG
						CCqGSM49AwEHA0IABEkwIk/9i9S9ftCQYlEhj7posxvsEKddiVDNE/NFKlm7
						xBPZYwJOu+v84SkAY5d/P0p9OsjthAAWKGASJYBItGSgCgQIIHNrcwIAAAAw
						CgYIKoZIzj0EAwIDRwAwRAIgHU83XIiKQrKl0aoXCB+yJ5i05MQBRZ52f0zt
						yzsI34MCIF6QRIRaUsTcts4Q6f9Z/ME2fo8rEM34I6/KaMcD7+6q
						</data>
						<key>WifiAddress</key>
						<string>bc:4c:c4:14:58:ab</string>
					</dict>
				</dict>
				</plist>';

				$ActivationInfoXML64 = base64_encode($ActivationInfoXML);

				$private = "-----BEGIN RSA PRIVATE KEY-----\nMIICWwIBAAKBgQC3BKrLPIBabhpr+4SvuQHnbF0ssqRIQ67/1bTfArVuUF6p9sdc\nv70N+r8yFxesDmpTmKitLP06szKNAO1k5JVk9/P1ejz08BMe9eAb4juAhVWdfAIy\naJ7sGFjeSL015mAvrxTFcOM10F/qSlARBiccxHjPXtuWVr0fLGrhM+/AMQIDAQAB\nAoGACGW3bHHPNdb9cVzt/p4Pf03SjJ15ujMY0XY9wUm/h1s6rLO8+/10MDMEGMlE\ndcmHiWRkwOVijRHxzNRxEAMI87AruofhjddbNVLt6ppW2nLCK7cEDQJFahTW9GQF\nzpVRQXXfxr4cs1X3kutlB6uY2VGltxQFYsj5djv7D+A72A0CQQDZj1RGdxbeOo4X\nzxfA6n42GpZavTlM3QzGFoBJgCqqVu1JQOzooAMRT+NPfgoE8+usIVVB4Io0bCUT\nWLpkEytTAkEA11rzIpGIhFkPtNc/33fvBFgwUbsjTs1V5G6z5ly/XnG9ENfLblgE\nobLmSmz3irvBRWADiwUx5zY6FN/Dmti56wJAdiScakufcnyvzwQZ7Rwp/61+erYJ\nGNFtb2Cmt8NO6AOehcopHMZQBCWy1ecm/7uJ/oZ3avfJdWBI3fGv/kpemwJAGMXy\noDBjpu3j26bDRz6xtSs767r+VctTLSL6+O4EaaXl3PEmCrx/U+aTjU45r7Dni8Z+\nwdhIJFPdnJcdFkwGHwJAPQ+wVqRjc4h3Hwu8I6llk9whpK9O70FLo1FMVdaytElM\nyqzQ2/05fMb7F6yaWhu+Q2GGXvdlURiA3tY0CsfM0w==\n-----END RSA PRIVATE KEY-----";
				
				$FairPlayCertChain = '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';
				
				$pkeyid = openssl_pkey_get_private($private);
				openssl_sign($ActivationInfoXML, $signature, $pkeyid, 'sha1WithRSAEncryption');
				openssl_free_key($pkeyid);
				$ActivationInfoXMLSignature = base64_encode($signature);

				$data = '<?xml version="1.0" encoding="UTF-8"?>
				<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
				<plist version="1.0">
				<dict>
					<key>ActivationInfoComplete</key>
					<true/>
					<key>ActivationInfoXML</key>
					<data>'.$ActivationInfoXML64.'</data>
					<key>FairPlayCertChain</key>
					<data>'.$FairPlayCertChain.'</data>
					<key>FairPlaySignature</key>
					<data>'.$ActivationInfoXMLSignature.'</data>
					<key>RKCertification</key>
			    <data>
			    MIIB9zCCAZwCAQEwADCB2gIBATAKBggqhkjOPQQDAgNIADBFAiEAk0kFrgp9oIqPSyw4
			    CeWwPc1MAGYtjvghUvV+YvDGhicCIEE0vW+s4Zs61eFjJDzvVxAKbsHFNj7MtVrbr5zT
			    i4k5MFswFQYHKoZIzj0CAaAKBggqhkjOPQMBBwNCAARuSdhS4I5eL1IyV2c+G690w4DH
			    9DFQye4b8PMbQ7FKFnhGcUOXk0eTfeF4q+b+au3l22dbj1DdioLbCCbNFVyFoAoECCBz
			    a3NIAAAAohYEFIT4wv/S+twSVWiuIUZOBiBDJj+OMIG3AgEBMAoGCCqGSM49BAMCA0kA
			    MEYCIQDngLzCQYigVMuMh3dtsq8GxrcShp6QobrHkWEmtDwjWgIhAKeWSAcq9n+wgAav
			    LU5TYBDy2smBJPSJxlgnECyB29RsMFswFQYHKoZIzj0CAaAKBggqhkjOPQMBBwNCAASU
			    2VJGBNC+Hjw5KKv3qW9IFVBE5KdWnoMwJxku1j5+7lqSe2kYxYhT1rvPAt/r1/0wALzL
			    aY59NYA0Ax8rKWfWMAoGCCqGSM49BAMCA0kAMEYCIQDhoMxEfjuVQgqo9ol5O6Li1Omg
			    JMzaL4VCTNZVXfFv/AIhALdI44Q5KEuk0FwaycYSScndcuh5B88+NuFQn41isuwM
			    </data>
			    <key>RKSignature</key>
			    <data>
			    MEQCIBfETROMXro82io/uy53ChhYmoqvTsSSdL9K9YUxW+GLAiAhh9EZ4TRxuSqWoRqm
			    0cop5KHlreeLv+PwHKpXn9Vmfw==
			    </data>
			    <key>serverKP</key>
					<data>
					TlVMTA==
					</data>
					<key>signActRequest</key>
					<data>
					TlVMTA==
					</data>
				</dict>
				</plist>';
		    
			$url = 'https://albert.apple.com/deviceservices/deviceActivation';
			$data_info=urlencode($data);
			$post_data ="activation-info=".$data_info;
			$ch = curl_init(); 
			curl_setopt($ch, CURLOPT_URL , $url ); 
			curl_setopt($ch, CURLOPT_RETURNTRANSFER , 1); 
			curl_setopt($ch, CURLOPT_TIMEOUT , 60); 
			curl_setopt($ch, CURLOPT_VERBOSE, 0);
			curl_setopt($ch, CURLOPT_HEADER, 0);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array("Host: albert.apple.com", "Content-Type: application/x-www-form-urlencoded", "Connection: keep-alive", "Accept: *", "Accept-Language: en-US", "Content-Length: ".strlen($post_data), "User-Agent: iTunes/12.11.3 (Windows; Microsoft Windows 10 x64 (Build 19042); x64) AppleWebKit/7611.1022.4001.1 (dt:2)"));
			curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
			curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
			curl_setopt($ch, CURLOPT_USERAGENT , "iOS Device Activator (MobileActivation-353.200.48)" );
			curl_setopt($ch, CURLOPT_POST , 1); 
			curl_setopt($ch, CURLOPT_POSTFIELDS , $post_data);  

			$xml_response = curl_exec($ch); 
				    
				$encodedrequest = new DOMDocument;
				$encodedrequest->loadXML($xml_response);

			  $FairPlayKeyData=$encodedrequest->getElementsByTagName('data')->item(2)->nodeValue;
			  $DeviceCertificate=$encodedrequest->getElementsByTagName('data')->item(1)->nodeValue;

				return array($FairPlayKeyData, $DeviceCertificate);
				
				file_put_contents('ActivationFiles/'.$serialNumber.'/FPKD.pem', $FairPlayKeyData);
			}
			$FPDC=FPDC_ALL($activationRandomness,$deviceCertRequest,$uniqueDeviceID,$BuildVersion,$DeviceClass,$DeviceVariant,$ModelNumber,$OSType,$productType,$ProductVersion,$RegulatoryModelNumber,$UniqueChipID, $serialNumber);

			$FairPlayKeyData = $FPDC[0];
			$DeviceCertificate = $FPDC[1];
			if(empty($imei)==false && empty($meid)==true)
			{
			  $baseband_ticket=GETWILDCARDTICKETGSM($BasebandMasterKeyHash, $BasebandChipID, $BasebandSerialNumber, $BuildVersion, $productType, $productVersion, $RegulatoryModelNumber,$activationRandomness, $serialNumber);
$AccountToken = '{'.
	(isset($imei) ? "\n\t".'"InternationalMobileEquipmentIdentity" = "'.$imei.'";' : '').
	(isset($imsi) ? "\n\t".'"InternationalMobileSubscriberIdentity" = "'.$imsi.'";' : '').
	"\n\t".'"ActivityURL" = "https://albert.apple.com/deviceservices/activity";'.
	"\n\t".'"SerialNumber" = "'.$serialNumber.'";'.
	"\n\t".'"ProductType" = "'.$productType.'";'.
	(isset($meid) ? "\n\t".'"MobileEquipmentIdentifier" = "'.$meid.'";' : '').
	(isset($iccid) ? "\n\t".'"IntegratedCircuitCardIdentity" = "'.$iccid.'";' : '').
	"\n\t".'"UniqueDeviceID" = "'.$uniqueDeviceID.'";'.
	"\n\t".'"ActivationRandomness" = "'.$activationRandomness.'";'.
	($deviceClass == "iPhone" ? "\n\t".'"CertificateURL" = "https://albert.apple.com/deviceservices/certifyMe";' : '').
	($deviceClass == "iPhone" ? "\n\t".'"PhoneNumberNotificationURL" = "https://albert.apple.com/deviceservices/phoneHome";' : '').
	"\n\t".'"WildcardTicket" = "'.$baseband_ticket.'";'."".
	"\n".
'}';
			}
			else if(empty($imei)==false && empty($meid)==false)
			{ 
				$baseband_ticket=GETWILDCARDTICKETGSM($BasebandMasterKeyHash, $BasebandChipID, $BasebandSerialNumber, $BuildVersion, $productType, $productVersion, $RegulatoryModelNumber,$activationRandomness, $serialNumber);
$AccountToken ='{'.
	(isset($imei) ? "\n\t".'"InternationalMobileEquipmentIdentity" = "'.$imei.'";' : '').
	(isset($imsi) ? "\n\t".'"InternationalMobileSubscriberIdentity" = "'.$imsi.'";' : '').
	"\n\t".'"ActivityURL" = "https://albert.apple.com/deviceservices/activity";'.
	"\n\t".'"SerialNumber" = "'.$serialNumber.'";'.
	"\n\t".'"ProductType" = "'.$productType.'";'.
	(isset($meid) ? "\n\t".'"MobileEquipmentIdentifier" = "'.$meid.'";' : '').
	(isset($iccid) ? "\n\t".'"IntegratedCircuitCardIdentity" = "'.$iccid.'";' : '').
	"\n\t".'"UniqueDeviceID" = "'.$uniqueDeviceID.'";'.
	"\n\t".'"ActivationRandomness" = "'.$activationRandomness.'";'.
	($deviceClass == "iPhone" ? "\n\t".'"CertificateURL" = "https://albert.apple.com/deviceservices/certifyMe";' : '').
	($deviceClass == "iPhone" ? "\n\t".'"PhoneNumberNotificationURL" = "https://albert.apple.com/deviceservices/phoneHome";' : '').
	"\n\t".'"ActivationTicket" = "'.$baseband_ticket.'";'."".
	"\n".
'}';
			}
	$private_key = "-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQCzYmXsSN3d7UTU8f77wm9C0IIJAwCmAeixBwkmWxJl239RFe9P\nRbOPzk0WHTiEARBXToxx4V7eZxR12kiaTG/wRWVm6Jy1okz0U8HsmGKQsJS+EvKg\nrFx3FgdzclqXulBOZzBSHvAwTo+ypNPR+vhmeYeRL6HvTuZBjZQYKeDyzwIDAQAB\nAoGBAKL7vzFND1CpWIXGDe9+vIpPWiaH9NngGCRoCRcxXejv4qCwtksnQDtjrMRv\n7j55nPhGZPK/WuvlakCeAKM42eZF/q2gRBeAZJNQkSHBW9d/OEt7bla92Fj+8IjP\nA3cQ+eyo/KyNtF6OL9KE6ghMskKsGBkdMZkDJHMxVu+sK35pAkEA3QBbOwB4tPdK\n4w+RwufoTmmSDxTGO5uvpsBRnFQ4K0s3WfPjhumDQRBeic+HxTDY72O1/iDpTbL9\npTW4f5qeswJBAM/K108a370DybA87FYVvMDOGBJsudIzLLhNj4eP4pO2+Dai955Y\nqXTF1ntlOX7lD73QYFyrfrvMqWj43i3laXUCQFUymvkPAHm7T+pjCS1bW+pGtqEL\nwDQgm8GsKIocyZ6fG5KY/CD5irkdh2SXVd8GKst25CU5KNfkZfY31I2U3RMCQQC4\nDqGHNXPH1ooZrO1fF2QZmLSj5WD3u1K6ciFX3/DADUtyAgq6XSjFAdUJelFigH3g\nEaq5i0L4EMJi9EbBertdAkAdMef5SNkge26nq7nylq0/mVA0sEPTA/bSAMrZDVgV\n4UBLXq12y1pQArJ/8rzkdL4x6fak50qzupAa/Jer8kie\n-----END RSA PRIVATE KEY-----";

	$pkeyid2 = openssl_pkey_get_private($private_key);
	openssl_sign($AccountToken, $signature, $pkeyid2);
	openssl_free_key($pkeyid2);
	
	$accountTokenBase64= base64_encode($AccountToken);
	$accountTokenSignature= base64_encode($signature);
	
	/*$Fair = explode("<key>FairPlayKeyData</key>", $xml_response)[1];
	$FairPlayKey = explode("<data>", $Fair)[1];
	$FairPlayKeyData = explode("</data>", $FairPlayKey)[0];
	
    file_put_contents("ForBypass/".$serialNumber."/FairPlay", $FairPlayKeyData);
    file_put_contents("ForBypass/".$serialNumber."/Account", $accountTokenBase64);
    file_put_contents("ForBypass/".$serialNumber."/Signature", $accountTokenSignature);*/
    	if($UDC != null){$UniqueDeviceCertificate = '<key>UniqueDeviceCertificate</key><data>'.$UDC.'</data>';}/*
		$DC = explode("<key>DeviceCertificate</key>", $xml_response)[1];
		$CA = explode("<data>", $DC)[1];
		$CARoot = explode("</data>", $CA)[0];
		$DCA = explode("<key>AccountTokenCertificate</key>", $xml_response)[1];
		$CAA = explode("<data>", $DCA)[1];
		$CAARoot = explode("</data>", $CAA)[0];*/
	
	$ActivationRecord = '<plist version="1.0"><dict><key>'.($deviceClass == "iPhone" ? 'iphone' : 'device').'-activation</key><dict><key>activation-record</key><dict><key>unbrick</key><true/><key>DeviceCertificate</key><data>'.$DeviceCertificate.'</data><key>AccountTokenCertificate</key><data>LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURaekNDQWsrZ0F3SUJBZ0lCQWpBTkJna3Foa2lHOXcwQkFRVUZBREI1TVFzd0NRWURWUVFHRXdKVlV6RVQKTUJFR0ExVUVDaE1LUVhCd2JHVWdTVzVqTGpFbU1DUUdBMVVFQ3hNZFFYQndiR1VnUTJWeWRHbG1hV05oZEdsdgpiaUJCZFhSb2IzSnBkSGt4TFRBckJnTlZCQU1USkVGd2NHeGxJR2xRYUc5dVpTQkRaWEowYVdacFkyRjBhVzl1CklFRjFkR2h2Y21sMGVUQWVGdzB3TnpBME1UWXlNalUxTURKYUZ3MHhOREEwTVRZeU1qVTFNREphTUZzeEN6QUoKQmdOVkJBWVRBbFZUTVJNd0VRWURWUVFLRXdwQmNIQnNaU0JKYm1NdU1SVXdFd1lEVlFRTEV3eEJjSEJzWlNCcApVR2h2Ym1VeElEQWVCZ05WQkFNVEYwRndjR3hsSUdsUWFHOXVaU0JCWTNScGRtRjBhVzl1TUlHZk1BMEdDU3FHClNJYjNEUUVCQVFVQUE0R05BRENCaVFLQmdRREZBWHpSSW1Bcm1vaUhmYlMyb1BjcUFmYkV2MGQxams3R2JuWDcKKzRZVWx5SWZwcnpCVmRsbXoySkhZdjErMDRJekp0TDdjTDk3VUk3ZmswaTBPTVkwYWw4YStKUFFhNFVnNjExVApicUV0K25qQW1Ba2dlM0hYV0RCZEFYRDlNaGtDN1QvOW83N3pPUTFvbGk0Y1VkemxuWVdmem1XMFBkdU94dXZlCkFlWVk0d0lEQVFBQm80R2JNSUdZTUE0R0ExVWREd0VCL3dRRUF3SUhnREFNQmdOVkhSTUJBZjhFQWpBQU1CMEcKQTFVZERnUVdCQlNob05MK3Q3UnovcHNVYXEvTlBYTlBIKy9XbERBZkJnTlZIU01FR0RBV2dCVG5OQ291SXQ0NQpZR3UwbE01M2cyRXZNYUI4TlRBNEJnTlZIUjhFTVRBdk1DMmdLNkFwaGlkb2RIUndPaTh2ZDNkM0xtRndjR3hsCkxtTnZiUzloY0hCc1pXTmhMMmx3YUc5dVpTNWpjbXd3RFFZSktvWklodmNOQVFFRkJRQURnZ0VCQUY5cW1yVU4KZEErRlJPWUdQN3BXY1lUQUsrcEx5T2Y5ek9hRTdhZVZJODg1VjhZL0JLSGhsd0FvK3pFa2lPVTNGYkVQQ1M5Vgp0UzE4WkJjd0QvK2Q1WlFUTUZrbmhjVUp3ZFBxcWpubTlMcVRmSC94NHB3OE9OSFJEenhIZHA5NmdPVjNBNCs4CmFia29BU2ZjWXF2SVJ5cFhuYnVyM2JSUmhUekFzNFZJTFM2alR5Rll5bVplU2V3dEJ1Ym1taWdvMWtDUWlaR2MKNzZjNWZlREF5SGIyYnpFcXR2eDNXcHJsanRTNDZRVDVDUjZZZWxpblpuaW8zMmpBelJZVHh0UzZyM0pzdlpEaQpKMDcrRUhjbWZHZHB4d2dPKzdidFcxcEZhcjBaakY5L2pZS0tuT1lOeXZDcndzemhhZmJTWXd6QUc1RUpvWEZCCjRkK3BpV0hVRGNQeHRjYz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=</data><key>LDActivationVersion</key><integer>2</integer><key>FairPlayKeyData</key><data>'.$FairPlayKeyData.'</data><key>AccountToken</key><data>'.$accountTokenBase64.'</data><key>AccountTokenSignature</key><data>'.$accountTokenSignature.'</data>'.$UniqueDeviceCertificate.'</dict><key>show-settings</key><true/></dict></dict></plist>';
	$AR = str_replace("<key>iphone-activation</key><dict><key>activation-record</key><dict>", "", $ActivationRecord);
	$ARF = str_replace("</dict><key>show-settings</key><true/></dict>", "", $AR);
	include('Center.php');
	file_put_contents('ActivationFiles/'.$serialNumber.'/activation_record.plist', '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'.$ARF.'');
	header('Content-Type: application/xml');
	header('Content-Length: '.strlen($ActivationRecord));
		echo $ActivationRecord;
		die();
	
}
?>
