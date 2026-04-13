package iso7816

import "testing"

func TestParseResponse_Success(t *testing.T) {
	raw := []byte{0x01, 0x02, 0x90, 0x00}
	resp, err := ParseResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsSuccess() {
		t.Errorf("expected success, got SW=%04X", resp.StatusWord())
	}
	if len(resp.Data) != 2 || resp.Data[0] != 0x01 || resp.Data[1] != 0x02 {
		t.Errorf("unexpected data: %X", resp.Data)
	}
}

func TestParseResponse_NoData(t *testing.T) {
	raw := []byte{0x90, 0x00}
	resp, err := ParseResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsSuccess() {
		t.Errorf("expected success")
	}
	if resp.Data != nil {
		t.Errorf("expected nil data, got %X", resp.Data)
	}
}

func TestParseResponse_Error(t *testing.T) {
	raw := []byte{0x6A, 0x82}
	resp, err := ParseResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsSuccess() {
		t.Errorf("expected failure")
	}
	if resp.Err() == nil {
		t.Error("expected non-nil error")
	}
}

func TestParseResponse_TooShort(t *testing.T) {
	_, err := ParseResponse([]byte{0x90})
	if err == nil {
		t.Fatal("expected error for short response")
	}
}

func TestResponse_HasMoreData(t *testing.T) {
	raw := []byte{0x61, 0x10}
	resp, err := ParseResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.HasMoreData() {
		t.Error("expected HasMoreData=true")
	}
}
