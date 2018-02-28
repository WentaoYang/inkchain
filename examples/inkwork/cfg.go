
package main

const (
	// function
	GetWork			string = "getWork"
	Purchase 		string = "purchase"
	Sell			string = "sell"
	Query			string = "query"
	FreeHistory		string = "user_address ~ workId "	
)

const (
	Shape 	= iota 	
	Line			
	Shade			
	Angle
	DrawNum
	LineWith	
	Color		
	MaxAttr
)

// work_level
const (
	Common = iota	
	Rare		
	Brilliant	
	Epic		
	Legend			
)

// query_type
const (
	QueryStart = iota
	All
	Sale
	Self
	QueryEnd
)

type WorkDef struct {
	WorkId		string	`json:"work_id"`
	Level 		int 	`json:"level"`
	Birth		int64	`json:"birth"`
	Owner		string	`json:"owner"`
	Sale		int		`json:"sale"`	// 0not sale, 1sale
	Price 		int		`json:"price"`
	SaleTime	int64	`json:"sale_time"`
}
