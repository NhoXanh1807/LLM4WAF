"""

XSS: điều khiển trình duyệt đăng nhập vào DVWA, 
nhập payload, dựa vào các mục tiêu tấn công, 
sử dụng request/response listener của browser 
để kiểm tra có bất kỳ request lạ nào được gửi 
đi hay nhận về, kiểm tra sự thay đổi localStorage (stored), 
html content (chèn form, mã độc), window URL (trách redirect),
… nói chung là dựa vào tất cả các mục tiêu tấn công để viết 
thuật toán nhận diện bao phủ đầy đủ các biểu hiện, 
hậu quả tấn công để phát hiện bất kỳ loại xss payload nào.

"""